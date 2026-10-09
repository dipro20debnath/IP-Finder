import pytest

from ipfinder.analysis.ipv6_insights import (
    embedded_ipv4,
    insights,
    interface_id,
    multicast,
    structure,
)
from tests.conftest import ip


def _kinds(address):
    return {e["kind"]: e for e in embedded_ipv4(ip(address))}


def test_teredo_rfc_example():
    # Wikipedia/RFC 4380 example: server 65.54.227.120, client 192.0.2.45:40000, cone NAT.
    found = _kinds("2001:0:4136:e378:8000:63bf:3fff:fdd2")
    assert found["teredo_server"]["address"] == "65.54.227.120"
    client = found["teredo_client"]
    assert client["address"] == "192.0.2.45"
    assert client["client_port"] == 40000
    assert client["cone_bit"] is True
    assert client["random_flag_bits"] is False
    assert client["flags"] == "0x8000"
    assert "RFC 5991" in client["rfc"] and "deprecated" in client["flags_note"]
    assert client["category"] == "documentation"
    assert client["globally_reachable"] is False


def test_6to4():
    found = _kinds("2002:c000:204::1")
    assert found["6to4"]["address"] == "192.0.2.4"
    assert _kinds("2002:808:808::1")["6to4"]["globally_reachable"] is True


def test_nat64_and_mapped():
    assert _kinds("64:ff9b::8.8.8.8")["nat64"]["address"] == "8.8.8.8"
    assert _kinds("::ffff:192.168.1.1")["ipv4_mapped"]["category"] == "private"


def test_no_embedded_ipv4_for_native_address():
    assert embedded_ipv4(ip("2001:4860:4860::8888")) == []


def test_structure():
    st = structure(ip("2001:db8:1234:5678:9abc:def0:1234:5678"))
    assert st["prefix_32"] == "2001:db8::/32"
    assert st["prefix_48"] == "2001:db8:1234::/48"
    assert st["prefix_56"] == "2001:db8:1234:5600::/56"
    assert st["subnet_64"] == "2001:db8:1234:5678::/64"
    assert st["interface_id"] == "9abc:def0:1234:5678"


def test_eui64_mac_extraction():
    info = interface_id(ip("fe80::21a:2bff:fe3c:4d5e"))
    assert info["type"] == "eui64"
    assert info["mac"] == "00:1a:2b:3c:4d:5e"
    assert info["oui"] == "00:1a:2b"
    assert info["mac_universally_administered"] is True
    assert info["vendor"] is None


def test_eui64_vendor_lookup_is_used_for_universal_mac():
    seen = []

    def lookup(mac):
        seen.append(mac)
        return "Example Vendor Inc."

    info = interface_id(ip("2001:db8::21a:2bff:fe3c:4d5e"), lookup)
    assert info["vendor"] == "Example Vendor Inc."
    assert seen == ["00:1a:2b:3c:4d:5e"]


def test_eui64_locally_administered_mac_skips_vendor():
    # MAC 02:1a:2b:3c:4d:5e (locally administered) -> IID 001a:2bff:fe3c:4d5e
    info = interface_id(ip("fe80::1a:2bff:fe3c:4d5e"), lambda mac: "SHOULD NOT BE USED")
    assert info["mac"] == "02:1a:2b:3c:4d:5e"
    assert info["mac_universally_administered"] is False
    assert info["vendor"] is None
    assert "Locally administered" in info["vendor_note"]


@pytest.mark.parametrize(
    "address,ipv4,global_flag",
    [
        ("fe80::5efe:c000:201", "192.0.2.1", False),
        ("2001:db8::200:5efe:808:808", "8.8.8.8", True),
    ],
)
def test_isatap(address, ipv4, global_flag):
    info = interface_id(ip(address))
    assert info["type"] == "isatap"
    assert info["ipv4"] == ipv4
    assert info["ipv4_globally_unique_flag"] is global_flag


@pytest.mark.parametrize(
    "address,kind",
    [
        ("2001:db8:1:2::", "subnet_router_anycast"),
        ("2001:db8::fdff:ffff:ffff:ff80", "reserved_subnet_anycast"),
        ("2001:4860:4860::8888", "low_byte"),
        ("2606:4700:4700::1111", "low_byte"),
        ("2001:db8::c000:201", "possible_embedded_ipv4"),
        ("2001:db8::a1b2:c3d4:e5f6:789a", "opaque"),
        ("2a03:2880:f12f:83:face:b00c:0:25de", "opaque"),
        # 0.x.x.x is "this network", never a host: these are manual IDs, not IPv4
        ("2001:db8::1:1", "manual"),
        ("2001:db8::53:1", "manual"),
        ("2001:db8::1:0:0:1", "manual"),
    ],
)
def test_interface_id_types(address, kind):
    assert interface_id(ip(address))["type"] == kind


def test_mobile_ipv6_home_agents_anycast():
    info = interface_id(ip("2001:db8::fdff:ffff:ffff:fffe"))
    assert "126" in info["description"]
    assert "Home-Agents" in info["description"]


def test_possible_embedded_ipv4_value():
    assert interface_id(ip("2001:db8::c000:201"))["ipv4"] == "192.0.2.1"


@pytest.mark.parametrize(
    "address",
    [
        "::1",
        "::",
        "::ffff:8.8.8.8",
        "64:ff9b::808:808",
        "100::1",
        "ff02::1",
        "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    ],
)
def test_no_interface_id_analysis_where_it_does_not_apply(address):
    assert interface_id(ip(address)) is None


def test_multicast_scope_and_well_known():
    info = multicast(ip("ff02::1"))
    assert info["scope"] == "Link-Local"
    assert info["well_known"] == "All Nodes on the link"
    assert info["flags"] == {"transient": False, "prefix_based": False, "embedded_rp": False}


def test_multicast_flags_and_global_scope():
    info = multicast(ip("ff3e:30:2001:db8::1"))
    assert info["scope"] == "Global"
    assert info["flags"]["transient"] is True
    assert info["flags"]["prefix_based"] is True
    assert info["flags"]["embedded_rp"] is False


def test_solicited_node():
    # RFC 4291 example: 4037::01:800:200E:8C6C -> FF02::1:FF0E:8C6C
    info = multicast(ip("ff02::1:ff0e:8c6c"))
    assert "Solicited-Node" in info["well_known"]
    assert "0e:8c6c" in info["well_known"]


def test_multicast_none_for_unicast():
    assert multicast(ip("2001:db8::1")) is None


@pytest.mark.parametrize(
    "address,has_structure",
    [
        ("2001:4860:4860::8888", True),
        ("fd12:3456::1", True),
        ("fe80::21a:2bff:fe3c:4d5e", False),
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", False),
        ("ff02::1", False),
        ("::1", False),
        ("64:ff9b::808:808", False),
    ],
)
def test_structure_only_where_meaningful(address, has_structure):
    assert (insights(ip(address))["structure"] is not None) is has_structure


def test_teredo_rfc5991_random_bits():
    client = _kinds("2001:0:4136:e378:8c3a:63bf:3fff:fdd2")["teredo_client"]
    assert client["flags"] == "0x8c3a"
    assert client["random_flag_bits"] is True


def test_eui64_pattern_with_group_bit_is_not_a_device_mac():
    # IID 0300:00ff:fe00:0001 -> g bit set: a group address cannot be an interface's MAC
    called = []
    info = interface_id(ip("2001:db8::300:ff:fe00:1"), lambda mac: called.append(mac))
    assert info["type"] == "eui64_pattern_group_bit"
    assert "mac" not in info
    assert called == []


@pytest.mark.parametrize(
    "address,rfc",
    [
        ("2001:db8::200:5eff:fe00:5213", "RFC 6543"),  # Proxy Mobile IPv6
        ("2001:db8::200:5eff:fe00:0", "RFC 4291, RFC 5453"),
        ("2001:db8::200:5eff:feff:ffff", "RFC 4291, RFC 5453"),
    ],
)
def test_iana_reserved_interface_ids(address, rfc):
    info = interface_id(ip(address))
    assert info["type"] == "reserved_iid"
    assert info["rfc"] == rfc
    assert "mac" not in info


def test_just_outside_reserved_iid_block_is_eui64():
    assert interface_id(ip("2001:db8::200:5eff:fd00:1")) is not None
    assert interface_id(ip("2001:db8::200:5fff:fe00:1"))["type"] == "eui64"


@pytest.mark.parametrize("address", ["::ffff:224.0.0.1", "::ffff:169.254.1.1"])
def test_ipv4_mapped_never_reports_ipv6_multicast_or_structure(address):
    # Recent CPython patch releases answer is_multicast / is_link_local for mapped
    # addresses from the embedded IPv4; the result must not depend on the version.
    result = insights(ip(address))
    assert result["multicast"] is None
    assert result["structure"] is None
    assert result["interface_id"] is None
