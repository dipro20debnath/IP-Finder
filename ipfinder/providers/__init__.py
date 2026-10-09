"""Provider registry.

``default_providers()`` are implemented; which of them run depends on the
profile (quick / standard / full), API keys and downloaded databases.
``PLANNED_PROVIDERS`` describe the rest of the roadmap (ADVANCED_PLAN.md section 3)
so the ``sources`` command can show what is coming and which key each needs.
"""

from __future__ import annotations

from dataclasses import dataclass

from ipfinder.providers.base import Provider
from ipfinder.providers.cloud_ranges import CloudRangesProvider
from ipfinder.providers.cymru import TeamCymruProvider
from ipfinder.providers.geofeed import GeofeedProvider
from ipfinder.providers.internetdb import InternetDBProvider
from ipfinder.providers.ipapi import IpApiProvider
from ipfinder.providers.ipinfo_lite import IpinfoLiteProvider
from ipfinder.providers.maxmind import MaxMindProvider
from ipfinder.providers.offline import OfflineProvider
from ipfinder.providers.peeringdb import PeeringDBProvider
from ipfinder.providers.private_relay import PrivateRelayProvider
from ipfinder.providers.rdap import RDAPProvider
from ipfinder.providers.reverse_dns import ReverseDNSProvider
from ipfinder.providers.ripestat import RIPEstatProvider
from ipfinder.providers.tor import TorProvider
from ipfinder.providers.vpn_lists import VPNListsProvider


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
        RDAPProvider(),
        RIPEstatProvider(),
        ReverseDNSProvider(),
        TorProvider(),
        PrivateRelayProvider(),
        CloudRangesProvider(),
        InternetDBProvider(),
        PeeringDBProvider(),
        GeofeedProvider(),
        VPNListsProvider(),
    ]


PLANNED_PROVIDERS = (
    PlannedProvider("abuseipdb", "L9", 5, "ABUSEIPDB_API_KEY", "Abuse confidence score"),
    PlannedProvider("greynoise", "L9", 5, None, "Scanner / benign classification"),
    PlannedProvider("virustotal", "L9", 5, "VIRUSTOTAL_API_KEY", "Vendor verdicts"),
    PlannedProvider("otx", "L9", 5, "OTX_API_KEY", "AlienVault OTX pulses"),
    PlannedProvider("abuse.ch", "L9", 5, "ABUSECH_AUTH_KEY", "ThreatFox / URLhaus / Feodo"),
    PlannedProvider("spamhaus", "L9", 5, "SPAMHAUS_DQS_KEY", "DNSBL listing"),
    PlannedProvider("active", "L10", 7, None, "Ping, traceroute, TLS cert (opt-in only)"),
)
