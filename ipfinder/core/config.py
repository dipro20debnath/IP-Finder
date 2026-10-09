"""Settings and API keys, read from environment variables and an optional .env file.

Real environment variables win over .env (same rule as python-dotenv's default).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

KNOWN_KEYS = (
    "IPINFO_TOKEN",
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


def read_dotenv(path: str | Path) -> dict[str, str]:
    """Minimal .env parser: KEY=VALUE lines, '#' comments, optional 'export ' and quotes."""
    values: dict[str, str] = {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if key:
            values[key] = value
    return values


@dataclass(frozen=True)
class Config:
    profile: str = "standard"
    active_mode: bool = False
    timeout: float = 10.0
    oui_db_path: Path = Path("data/oui.csv")
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
        if merged.get("IPFINDER_OUI_DB"):
            settings["oui_db_path"] = Path(merged["IPFINDER_OUI_DB"])
        settings.update({k: v for k, v in overrides.items() if v is not None})
        config = cls(**settings)
        if config.profile not in PROFILES:
            raise ValueError(f"Unknown profile '{config.profile}'; choose from {PROFILES}")
        return config

    def key_for(self, name: str) -> str | None:
        return self.api_keys.get(name)
