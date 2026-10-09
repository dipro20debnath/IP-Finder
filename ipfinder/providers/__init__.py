"""Provider registry.

``default_providers()`` are implemented; which of them run depends on the
profile (quick / standard / full), API keys and downloaded databases.
``PLANNED_PROVIDERS`` describe the rest of the roadmap (ADVANCED_PLAN.md section 3)
so the ``sources`` command can show what is coming and which key each needs.
"""

from __future__ import annotations

from dataclasses import dataclass

from ipfinder.providers.base import Provider
from ipfinder.providers.cymru import TeamCymruProvider
from ipfinder.providers.ipapi import IpApiProvider
from ipfinder.providers.ipinfo_lite import IpinfoLiteProvider
from ipfinder.providers.maxmind import MaxMindProvider
from ipfinder.providers.offline import OfflineProvider
from ipfinder.providers.peeringdb import PeeringDBProvider


@dataclass(frozen=True)
class PlannedProvider:
    name: str
    layer: str
    phase: int
    key: str | None
    description: str


def default_providers() -> list[Provider]:
    return [
        OfflineProvider(),
        IpApiProvider(),
        IpinfoLiteProvider(),
        MaxMindProvider(),
        TeamCymruProvider(),
        PeeringDBProvider(),
    ]


PLANNED_PROVIDERS = (
    PlannedProvider("rdap", "L4", 3, None, "Registration, net range, abuse contact"),
    PlannedProvider("ripestat", "L5", 3, None, "BGP prefix, RPKI, neighbours"),
    PlannedProvider("dns", "L6", 3, None, "PTR and forward-confirmed reverse DNS"),
    PlannedProvider("geofeed", "L2", 3, None, "Operator-published location (RFC 8805/9632)"),
    PlannedProvider("cloud-ranges", "L7", 4, None, "AWS/GCP/Azure/Cloudflare range match"),
    PlannedProvider("tor", "L7", 4, None, "Tor exit node list"),
    PlannedProvider("private-relay", "L7", 4, None, "iCloud Private Relay egress ranges"),
    PlannedProvider("internetdb", "L8", 4, None, "Shodan InternetDB: ports, CPEs, CVEs"),
    PlannedProvider("abuseipdb", "L9", 5, "ABUSEIPDB_API_KEY", "Abuse confidence score"),
    PlannedProvider("greynoise", "L9", 5, None, "Scanner / benign classification"),
    PlannedProvider("virustotal", "L9", 5, "VIRUSTOTAL_API_KEY", "Vendor verdicts"),
    PlannedProvider("otx", "L9", 5, "OTX_API_KEY", "AlienVault OTX pulses"),
    PlannedProvider("abuse.ch", "L9", 5, "ABUSECH_AUTH_KEY", "ThreatFox / URLhaus / Feodo"),
    PlannedProvider("spamhaus", "L9", 5, "SPAMHAUS_DQS_KEY", "DNSBL listing"),
    PlannedProvider("active", "L10", 7, None, "Ping, traceroute, TLS cert (opt-in only)"),
)
