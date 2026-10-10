"""Provider registry.

``default_providers()`` are implemented; which of them run depends on the
profile (quick / standard / full), API keys and downloaded databases.
``PLANNED_PROVIDERS`` describe the rest of the roadmap (ADVANCED_PLAN.md section 3)
so the ``sources`` command can show what is coming and which key each needs.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ipfinder.core.config import Config
from ipfinder.providers.abusech import ThreatFoxProvider, URLhausProvider
from ipfinder.providers.abuseipdb import AbuseIPDBProvider
from ipfinder.providers.active import RTTProvider, TLSCertProvider, TracerouteProvider
from ipfinder.providers.base import Provider
from ipfinder.providers.cloud_ranges import CloudRangesProvider
from ipfinder.providers.cymru import TeamCymruProvider
from ipfinder.providers.geofeed import GeofeedProvider
from ipfinder.providers.greynoise import GreyNoiseProvider
from ipfinder.providers.internetdb import InternetDBProvider
from ipfinder.providers.ipapi import IpApiProvider
from ipfinder.providers.ipinfo_lite import IpinfoLiteProvider
from ipfinder.providers.list_base import ListProvider
from ipfinder.providers.maxmind import MaxMindProvider
from ipfinder.providers.offline import OfflineProvider
from ipfinder.providers.otx import OTXProvider
from ipfinder.providers.peeringdb import PeeringDBProvider
from ipfinder.providers.private_relay import PrivateRelayProvider
from ipfinder.providers.rdap import RDAPProvider
from ipfinder.providers.reverse_dns import ReverseDNSProvider
from ipfinder.providers.ripestat import RIPEstatProvider
from ipfinder.providers.spamhaus import SpamhausProvider
from ipfinder.providers.threat_lists import FeodoProvider, SpamhausDropProvider
from ipfinder.providers.tor import TorProvider
from ipfinder.providers.virustotal import VirusTotalProvider
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
        FeodoProvider(),
        AbuseIPDBProvider(),
        GreyNoiseProvider(),
        VirusTotalProvider(),
        OTXProvider(),
        ThreatFoxProvider(),
        URLhausProvider(),
        SpamhausProvider(),
        PeeringDBProvider(),
        GeofeedProvider(),
        VPNListsProvider(),
        SpamhausDropProvider(),
        RTTProvider(),
        TracerouteProvider(),
        TLSCertProvider(),
    ]


PLANNED_PROVIDERS: tuple[PlannedProvider, ...] = ()


def _needs(provider: Provider, config: Config) -> str:
    if provider.requires_key:
        return provider.requires_key
    if provider.optional_key:
        return f"{provider.optional_key} (optional)"
    if provider.required_files(config):
        return "GeoLite2 .mmdb files"
    if isinstance(provider, ListProvider):
        return "ipfinder update-lists"
    if provider.active:
        return "--active (authorised targets only)"
    return "-"


def source_overview(config: Config) -> list[dict]:
    """Every source: whether it is ready (judged with the full profile, so a missing
    key shows up) and what it needs. The "sources" command and the web dashboard
    show this."""
    full = replace(config, profile="full")
    rows = []
    for p in default_providers():
        reason = p.unavailable_reason(full)
        rows.append(
            {
                "name": p.name,
                "layer": p.layer,
                "profiles": list(p.profiles),
                "ready": reason is None,
                "status": "ready" if reason is None else reason,
                "needs": _needs(p, config),
            }
        )
    return rows
