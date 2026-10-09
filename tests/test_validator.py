import pytest

from ipfinder.core.validator import InvalidIPError, parse_ip
from tests.conftest import ip


@pytest.mark.parametrize(
    "raw,expected,fmt,port",
    [
        ("8.8.8.8", "8.8.8.8", "ipv4", None),
        ("  8.8.8.8 \n", "8.8.8.8", "ipv4", None),
        ("2001:4860:4860::8888", "2001:4860:4860::8888", "ipv6", None),
        ("2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888", "ipv6", None),
        ("8.8.8.8:53", "8.8.8.8", "ipv4", 53),
        ("[2001:db8::1]", "2001:db8::1", "ipv6", None),
        ("[2001:db8::1]:443", "2001:db8::1", "ipv6", 443),
        ("[::1]:0", "::1", "ipv6", 0),
        ("http://8.8.8.8:8080/path?q=1", "8.8.8.8", "ipv4", 8080),
        ("https://[2001:db8::1]/", "2001:db8::1", "ipv6", None),
        ("134744072", "8.8.8.8", "integer", None),
        ("0", "0.0.0.0", "integer", None),
        ("4294967295", "255.255.255.255", "integer", None),
        ("4294967296", "::1:0:0", "integer", None),
    ],
)
def test_valid_inputs(raw, expected, fmt, port):
    parsed = parse_ip(raw)
    assert parsed.address == ip(expected)
    assert parsed.input_format == fmt
    assert parsed.port == port
    assert parsed.raw == raw


@pytest.mark.parametrize(
    "raw",
    [
        "৮.৮.৮.৮",  # Bengali digits
        "٨.٨.٨.٨",  # Arabic-Indic digits
        "８.８.８.８",  # full-width digits
    ],
)
def test_non_ascii_digits_are_normalised(raw):
    parsed = parse_ip(raw)
    assert parsed.address == ip("8.8.8.8")
    assert any("Normalised" in n for n in parsed.notes)


def test_zone_id_is_set_aside():
    parsed = parse_ip("fe80::1%eth0")
    assert parsed.address == ip("fe80::1")
    assert parsed.scope_id == "eth0"
    assert parsed.address.scope_id is None


def test_url_note():
    assert "Extracted host from URL: 8.8.8.8" in parse_ip("http://8.8.8.8/").notes


@pytest.mark.parametrize(
    "raw,message_part",
    [
        ("", "Empty input"),
        ("   ", "Empty input"),
        ("256.1.1.1", "Octet 256"),
        ("1.2.3", "has 3 part(s)"),
        ("1.2.3.4.5", "has 5 part(s)"),
        ("010.1.1.1", "Leading zero"),
        ("8.8.8.08", "Leading zero"),
        ("google.com", "looks like a hostname"),
        ("8.8.8.0/24", "network (CIDR)"),
        ("2001:db8::/32", "network (CIDR)"),
        ("abc", "not a valid IPv4 or IPv6"),
        ("1.2.3.4:70000", "out of range"),
        ("[2001:db8::1]:99999", "out of range"),
        ("http://8.8.8.8:99999/", "Could not parse URL"),
        ("http:///path", "No host found"),
        (str(2**128), "larger than any IPv6"),
        ("2001:db8::g", "not a valid IPv4 or IPv6"),
        ("[bold]x[/bold]", "not a valid IPv4 or IPv6"),
        ("a/b", "not a valid IPv4 or IPv6"),
        ("8.8.8.8/33", "not a valid IPv4 or IPv6"),
        ("localhost", "looks like a hostname"),
    ],
)
def test_invalid_inputs(raw, message_part):
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip(raw)
    assert message_part in excinfo.value.message


def test_leading_zero_hint_mentions_cve():
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip("010.1.1.1")
    assert "CVE-2021-29921" in excinfo.value.hint
    assert "CVE-2021-29921" in str(excinfo.value)


def test_none_input():
    with pytest.raises(InvalidIPError):
        parse_ip(None)
