"""Hints from a reverse-DNS (PTR) hostname.

Operators choose these names freely, so every result here is a hint, never a fact.
Anyone who controls an address's reverse zone can publish any name (even
"mail.google.com"); only a forward-confirmed name (FCrDNS) is trustworthy.
"""

from __future__ import annotations

import ipaddress
import re

# Reverse-DNS suffixes that cloud and hosting companies assign automatically.
KNOWN_SUFFIXES = (
    ("amazonaws.com", "cloud", "Amazon Web Services (EC2 or another AWS service)"),
    ("googleusercontent.com", "cloud", "Google Cloud (customer virtual machine)"),
    ("1e100.net", "cloud", "Google's own servers"),
    ("cloudapp.azure.com", "cloud", "Microsoft Azure"),
    ("cloudapp.net", "cloud", "Microsoft Azure"),
    ("linodeusercontent.com", "cloud", "Akamai Cloud (Linode)"),
    ("members.linode.com", "cloud", "Akamai Cloud (Linode)"),
    ("vultrusercontent.com", "cloud", "Vultr"),
    ("your-server.de", "hosting", "Hetzner"),
    ("contaboserver.net", "hosting", "Contabo"),
    ("ovh.net", "hosting", "OVHcloud"),
    ("poneytelecom.eu", "hosting", "Scaleway"),
    ("scw.cloud", "cloud", "Scaleway"),
    ("sl-reverse.com", "hosting", "IBM Cloud (SoftLayer)"),
    ("akamaitechnologies.com", "cdn", "Akamai CDN"),
)

# Name parts (digits removed) and what they usually mean.
TOKENS = {
    "access": (
        "adsl",
        "vdsl",
        "xdsl",
        "dsl",
        "cable",
        "ftth",
        "fttx",
        "fttb",
        "fttp",
        "fiber",
        "fibre",
        "broadband",
        "dhcp",
        "dyn",
        "dynamic",
        "pool",
        "dialup",
        "dial",
        "ppp",
        "pppoe",
        "cust",
        "customer",
        "cpe",
        "res",
        "residential",
        "home",
        "hsd",
    ),
    "static": ("static", "biz", "business"),
    "mobile": ("mobile", "mob", "lte", "gprs", "umts", "cellular"),
    "server": ("server", "srv", "vps", "dedicated", "dedi", "colo", "hosting", "cloud", "vm"),
    "mail": ("mail", "smtp", "mx"),
    "infrastructure": ("router", "rtr", "gw", "gateway", "core", "border"),
    "anonymity": ("vpn", "proxy", "torexit"),
}
MEANING = {
    "access": "home or small-office access line (often a dynamic address)",
    "static": "static address, often a business line",
    "mobile": "mobile (cellular) network",
    "server": "server or hosting",
    "mail": "mail server",
    "infrastructure": "network equipment (router or gateway interface)",
    "anonymity": "the operator named it like a VPN, proxy or Tor relay",
}
_MOBILE_GENERATIONS = re.compile(r"^[345]g$")
_SPLIT = re.compile(r"[.\-_]+")


def _encodes_address(hostname: str, target: str) -> str | None:
    """Return the form in which the hostname spells out the IPv4 address, if any."""
    ip = ipaddress.ip_address(target)
    if ip.version != 4:
        return None
    octets = [str(o) for o in ip.packed]
    forms = {
        "dotted": ".".join(octets),
        "dashed": "-".join(octets),
        "underscored": "_".join(octets),
        "reversed dotted": ".".join(reversed(octets)),
        "reversed dashed": "-".join(reversed(octets)),
        "zero-padded": "".join(f"{o:03d}" for o in ip.packed),
        "hex": ip.packed.hex(),
    }
    for label, form in forms.items():
        if re.search(rf"(?<![0-9a-f]){re.escape(form)}(?![0-9a-f])", hostname):
            return label
    return None


def hostname_hints(hostname: str, target: str) -> list[dict[str, str]]:
    name = hostname.lower().rstrip(".")
    hints = []
    encoded = _encodes_address(name, target)
    if encoded:
        hints.append(
            {
                "category": "generated",
                "hint": "name is generated from the address (typical for ISP pools and clouds)",
                "evidence": f"{encoded} address in the name",
            }
        )
    for suffix, category, owner in KNOWN_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            hints.append({"category": category, "hint": owner, "evidence": suffix})
            return hints  # the suffix says more than any word in the name

    labels = name.split(".")
    # Ignore the registered domain (last two labels): "home.example" says nothing.
    words = [w for label in labels[:-2] for w in _SPLIT.split(label) if w]
    pairs = [(word, re.sub(r"\d+", "", word)) for word in words]
    bare_words = {bare for _, bare in pairs}
    seen = set()
    for word, bare in pairs:
        if _MOBILE_GENERATIONS.match(word):
            category = "mobile"
        elif bare in ("tor", "exit") and {"tor", "exit"} <= bare_words:
            category = "anonymity"  # "tor" alone is often Toronto
        else:
            category = next((c for c, tokens in TOKENS.items() if bare in tokens), None)
        if category and category not in seen:
            seen.add(category)
            hints.append({"category": category, "hint": MEANING[category], "evidence": word})
    return hints
