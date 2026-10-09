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


def test_byte_order_mark_is_ignored():
    assert parse_ip("\ufeff8.8.8.8").address == ip("8.8.8.8")


@pytest.mark.parametrize(
    "raw,message_part",
    [
        ("9" * 5000, "too long"),
        ("9" * 2000, "larger than any IPv6"),
        ("1.2.3.4:" + "9" * 2000, "out of range"),
        ("1.1.1." + "9" * 2000, "out of range"),
        ("1.1.1.0001", "Leading zero"),
    ],
)
def test_huge_numbers_give_clean_errors(raw, message_part):
    # Python 3.10.7+ refuses int() on >4300-digit strings with a plain ValueError;
    # the validator must never let that escape.
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip(raw)
    assert message_part in excinfo.value.message


@pytest.mark.parametrize(
    "raw,reads_as",
    [
        ("0x7f000001", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("0xC0A80001", "192.168.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("1.2.3", "1.2.0.3"),
        ("010.1.1.1", "8.1.1.1"),
    ],
)
def test_inet_aton_forms_are_explained(raw, reads_as):
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip(raw)
    assert reads_as in excinfo.value.hint
    assert "hostname" not in excinfo.value.message


def test_inet_aton_helper():
    from ipfinder.core.validator import inet_aton

    assert str(inet_aton("0x08080808")) == "8.8.8.8"
    assert str(inet_aton("8.8.2056")) == "8.8.8.8"
    assert inet_aton("1.2.3.256") is None
    assert inet_aton("08.1.1.1") is None  # 8 is not an octal digit
    assert inet_aton("1.2.3.4.5") is None


@pytest.mark.parametrize(
    "raw",
    ["\x1b[2J\x1b[31mevil", "\x1b]52;c;ZWNobyBwd25lZA==\x1b\\", "8.8.8.8\u200b"],
)
def test_control_characters_are_escaped_in_messages(raw):
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip(raw)
    assert "\x1b" not in str(excinfo.value)
    assert "\u200b" not in str(excinfo.value)


def test_zone_id_with_control_characters_is_rejected():
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip("fe80::1%\x1b[2J")
    assert "Zone ID" in excinfo.value.message
    assert "\x1b" not in excinfo.value.message


def test_url_backslash_follows_browsers():
    parsed = parse_ip("http://1.1.1.1\\@8.8.8.8/")
    assert parsed.address == ip("1.1.1.1")
    assert any("WHATWG" in n for n in parsed.notes)


def test_url_userinfo_note():
    parsed = parse_ip("http://user:pass@8.8.8.8/")
    assert parsed.address == ip("8.8.8.8")
    assert any("user-info" in n for n in parsed.notes)


@pytest.mark.parametrize(
    "raw",
    [
        "\x01http://1.1.1.1\\@8.8.8.8/",
        "\x00http://1.1.1.1\\@8.8.8.8/",
        "ht\ttp://1.1.1.1\\@8.8.8.8/",
        "h\nttp://1.1.1.1\\@8.8.8.8/",
        "http\r://1.1.1.1\\@8.8.8.8/",
    ],
)
def test_url_preprocessing_matches_browsers(raw):
    # WHATWG: strip C0 controls/space at the ends and drop tabs/newlines first.
    assert parse_ip(raw).address == ip("1.1.1.1")


@pytest.mark.parametrize(
    "raw,reads_as",
    [
        ("0177", "0.0.0.127"),
        ("010", "0.0.0.8"),
        ("017700000001", "127.0.0.1"),
        ("http://017700000001/", "127.0.0.1"),
    ],
)
def test_integer_with_leading_zero_is_ambiguous(raw, reads_as):
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip(raw)
    assert "Leading zero" in excinfo.value.message
    assert reads_as in excinfo.value.hint


def test_url_integer_host_cannot_be_ipv6():
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip("http://4294967296/")
    assert "larger than any IPv4" in excinfo.value.message
    assert parse_ip("http://134744072/").address == ip("8.8.8.8")


@pytest.mark.parametrize(
    "raw,reads_as", [("1.2.3.0000000000004", "1.2.3.4"), ("0000000000010.1.1.1", "8.1.1.1")]
)
def test_zero_padded_octets_are_leading_zero_not_out_of_range(raw, reads_as):
    with pytest.raises(InvalidIPError) as excinfo:
        parse_ip(raw)
    assert "Leading zero" in excinfo.value.message
    assert reads_as in excinfo.value.hint


def test_inet_aton_matches_glibc_on_many_inputs():
    import random
    import socket
    import sys

    from ipfinder.core.validator import inet_aton

    if not sys.platform.startswith("linux"):
        pytest.skip("reference behaviour is glibc inet_aton")
    rng = random.Random(29921)
    parts = [
        "0",
        "00",
        "07",
        "08",
        "010",
        "0x",
        "0x1f",
        "0XfF",
        "255",
        "256",
        "4095",
        "65535",
        "16777215",
        "4294967295",
        "4294967296",
        "0x100000000",
        "1",
    ]
    for _ in range(3000):
        text = ".".join(rng.choice(parts) for _ in range(rng.randint(1, 4)))
        try:
            expected = socket.inet_aton(text)
        except OSError:
            expected = None
        got = inet_aton(text)
        assert (got.packed if got else None) == expected, text
