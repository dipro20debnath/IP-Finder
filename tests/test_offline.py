import pytest

from tests.conftest import offline


@pytest.mark.parametrize(
    "raw,eligible,target",
    [
        ("8.8.8.8", True, "8.8.8.8"),
        ("2001:4860:4860::8888", True, "2001:4860:4860::8888"),
        ("192.168.1.10", False, None),
        ("100.64.1.1", False, None),
        ("127.0.0.1", False, None),
        ("::1", False, None),
        ("fe80::1", False, None),
        ("2001:db8::1", False, None),
        ("3fff::1", False, None),
        ("224.0.0.251", False, None),
        # IPv6 wrappers: the embedded IPv4 is what online databases know
        ("::ffff:8.8.8.8", True, "8.8.8.8"),
        ("64:ff9b::8.8.8.8", True, "8.8.8.8"),
        ("2002:808:808::1", True, "8.8.8.8"),
        # Teredo client 8.8.8.8:40000 via server 65.54.227.120
        ("2001:0:4136:e378:8000:63bf:f7f7:f7f7", True, "8.8.8.8"),
        # Teredo whose client is a documentation address: no lookup, even though
        # the Teredo *server* is public (its location says nothing about the user)
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", False, None),
        ("::ffff:192.168.1.1", False, None),
        ("2002:c000:204::1", False, None),
        # ISATAP inside a global prefix: the IPv6 itself is what gets looked up
        ("2001:4860:4860:0:200:5efe:808:808", True, "2001:4860:4860:0:200:5efe:808:808"),
    ],
)
def test_lookup_decision(raw, eligible, target):
    decision = offline(raw)["lookup"]
    assert decision["eligible"] is eligible
    assert decision["target"] == target
    assert decision["reason"]


def test_teredo_reason_names_the_non_public_client():
    reason = offline("2001:0:4136:e378:8000:63bf:3fff:fdd2")["lookup"]["reason"]
    assert "teredo_client 192.0.2.45 is documentation" in reason
    assert "65.54.227.120" not in reason


def test_private_reason_cites_rfc():
    assert "RFC 1918" in offline("10.1.2.3")["lookup"]["reason"]


def test_report_shape_ipv4():
    data = offline("8.8.8.8")
    assert data["ip"] == "8.8.8.8"
    assert data["version"] == 4
    assert data["classification"]["category"] == "global_unicast"
    assert data["ipv4"]["historic_class"]["class"] == "A"
    assert "ipv6" not in data
    assert data["python_ipaddress"]["agrees_with_iana_table"] is True


def test_report_shape_ipv6():
    data = offline("fe80::21a:2bff:fe3c:4d5e%eth0")
    assert data["ip"] == "fe80::21a:2bff:fe3c:4d5e"
    assert data["scope_id"] == "eth0"
    assert data["ipv6"]["interface_id"]["mac"] == "00:1a:2b:3c:4d:5e"
    assert "ipv4" not in data


def test_no_agreement_flag_when_registry_says_na():
    # 6to4 is "N/A" in the IANA registry, so there is nothing to compare with.
    assert "agrees_with_iana_table" not in offline("2002:808:808::1")["python_ipaddress"]


def test_port_is_reported():
    assert offline("[2001:db8::1]:443")["port"] == 443
