"""Settings and API keys, read from environment variables and an optional .env file.

Real environment variables win over .env (same rule as python-dotenv's default).
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

KNOWN_KEYS = (
    "IPINFO_TOKEN",
    "MAXMIND_ACCOUNT_ID",
    "MAXMIND_LICENSE_KEY",
    "PEERINGDB_API_KEY",
    "ABUSEIPDB_API_KEY",
    "GREYNOISE_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "OTX_API_KEY",
    "ABUSECH_AUTH_KEY",
    "SPAMHAUS_DQS_KEY",
)

PROFILES = ("quick", "standard", "full")


_EXPORT = re.compile(r"export\s+")
_INLINE_COMMENT = re.compile(r"\s#")


_ESCAPES = {
    '"': {
        "\\": "\\",
        '"': '"',
        "'": "'",
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
    },
    "'": {"\\": "\\", "'": "'"},
}


def _parse_value(value: str) -> str | None:
    """Value semantics of python-dotenv: inside "double quotes" backslash escapes
    (\\n, \\", ...) work, inside 'single quotes' only \\' and \\\\; an unterminated
    quote makes the line invalid (None). Unquoted, whitespace + '#' starts a comment."""
    if value[:1] in ("'", '"'):
        quote, escapes = value[0], _ESCAPES[value[0]]
        out, i = [], 1
        while i < len(value):
            ch = value[i]
            if ch == "\\" and i + 1 < len(value) and value[i + 1] in escapes:
                out.append(escapes[value[i + 1]])
                i += 2
            elif ch == quote:
                return "".join(out)
            else:
                out.append(ch)
                i += 1
        return None
    match = _INLINE_COMMENT.search(value)
    return (value[: match.start()] if match else value).strip()


def read_dotenv(path: str | Path) -> dict[str, str]:
    """Minimal .env parser: KEY=VALUE lines, '#' comments (whole-line or after
    whitespace), optional 'export ' prefix and quotes."""
    values: dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        line = _EXPORT.sub("", line, count=1) if _EXPORT.match(line) else line
        key, value = line.split("=", 1)
        key = key.strip()
        parsed = _parse_value(value.strip())
        if key and parsed is not None:
            values[key] = parsed
    return values


# Path settings that can be overridden from the environment / .env
_PATH_SETTINGS = {
    "IPFINDER_OUI_DB": "oui_db_path",
    "IPFINDER_CACHE": "cache_path",
    "IPFINDER_MAXMIND_CITY_DB": "maxmind_city_db",
    "IPFINDER_MAXMIND_ASN_DB": "maxmind_asn_db",
    "IPFINDER_LISTS_DIR": "lists_dir",
}


@dataclass(frozen=True)
class Config:
    profile: str = "standard"
    active_mode: bool = False
    timeout: float = 10.0
    use_cache: bool = True
    oui_db_path: Path = Path("data/oui.csv")
    cache_path: Path = Path("data/cache.sqlite")
    maxmind_city_db: Path = Path("data/GeoLite2-City.mmdb")
    maxmind_asn_db: Path = Path("data/GeoLite2-ASN.mmdb")
    lists_dir: Path = Path("data/lists")  # Tor, cloud, Private Relay, VPN lists
    my_location: str | None = None  # "lat,lon" of this computer, for the RTT check
    api_keys: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        env: Mapping[str, str] | None = None,
        dotenv_path: str | Path | None = ".env",
        **overrides,
    ) -> Config:
        env = os.environ if env is None else env
        merged = dict(read_dotenv(dotenv_path)) if dotenv_path else {}
        merged.update(
            {k: v for k, v in env.items() if k in KNOWN_KEYS or k.startswith("IPFINDER_")}
        )
        keys = {k: merged[k] for k in KNOWN_KEYS if merged.get(k)}
        settings = {"api_keys": keys}
        for env_name, attr in _PATH_SETTINGS.items():
            if merged.get(env_name):
                settings[attr] = Path(merged[env_name])
        if merged.get("IPFINDER_LOCATION"):
            settings["my_location"] = merged["IPFINDER_LOCATION"]
        settings.update({k: v for k, v in overrides.items() if v is not None})
        config = cls(**settings)
        if config.profile not in PROFILES:
            raise ValueError(f"Unknown profile '{config.profile}'; choose from {PROFILES}")
        return config

    def key_for(self, name: str) -> str | None:
        return self.api_keys.get(name)
