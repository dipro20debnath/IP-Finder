"""AbuseIPDB: how often an address has been reported for abuse, and for what.

  GET https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90&verbose
  headers: Key: <ABUSEIPDB_API_KEY>, Accept: application/json
  {"data": {"abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt",
            "usageType", "isp", "domain", "hostnames", "isTor", "isWhitelisted",
            "countryCode", "reports": [{"reportedAt", "categories": [..], ...}]}}
The free plan allows 1,000 checks a day; the remaining quota comes back in the
X-RateLimit-Remaining header. Report comments are user-written, so only the
categories and dates are kept.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from ipfinder.core.http import request_json
from ipfinder.providers.base import HOUR, LookupContext, Provider, ProviderError
from ipfinder.providers.common import clean

URL = "https://api.abuseipdb.com/api/v2/check"
MAX_AGE_DAYS = 90

# https://www.abuseipdb.com/categories
CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def parse_check(data: Any) -> dict[str, Any]:
    body = data.get("data") if isinstance(data, dict) else None
    if not isinstance(body, dict):
        raise ProviderError("AbuseIPDB returned an unexpected response")
    counts: Counter = Counter()
    for report in body.get("reports") or []:
        if isinstance(report, dict):
            counts.update(c for c in report.get("categories") or [] if isinstance(c, int))
    result = {
        "score": body.get("abuseConfidenceScore"),
        "total_reports": body.get("totalReports"),
        "distinct_reporters": body.get("numDistinctUsers"),
        "last_reported": clean(body.get("lastReportedAt")),
        "usage_type": clean(body.get("usageType")),
        "isp": clean(body.get("isp")),
        "domain": clean(body.get("domain")),
        "country_code": clean(body.get("countryCode")),
        "is_tor": body.get("isTor"),
        "is_whitelisted": body.get("isWhitelisted"),
        "hostnames": [h for h in body.get("hostnames") or [] if isinstance(h, str)],
        "categories": [
            {"id": cid, "name": CATEGORIES.get(cid, f"category {cid}"), "reports": n}
            for cid, n in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        ][:8],
        "max_age_days": MAX_AGE_DAYS,
    }
    return {k: v for k, v in result.items() if v is not None}


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    layer = "L9"
    description = "Abuse reports: confidence score, report count, categories"
    profiles = ("full",)
    requires_key = "ABUSEIPDB_API_KEY"
    cache_ttl = 6 * HOUR

    async def lookup(self, ctx: LookupContext) -> dict[str, Any]:
        response, data = await request_json(
            ctx.session,
            "GET",
            URL,
            params={"ipAddress": ctx.target, "maxAgeInDays": MAX_AGE_DAYS, "verbose": ""},
            headers={"Key": ctx.config.key_for(self.requires_key), "Accept": "application/json"},
        )
        result = parse_check(data)
        remaining = response.headers.get("x-ratelimit-remaining", "").strip()
        if remaining.isdigit():
            result["quota_remaining"] = int(remaining)
        result["link"] = f"https://www.abuseipdb.com/check/{ctx.target}"
        return result
