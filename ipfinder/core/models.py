"""Data model shared by providers, the orchestrator and the output renderers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ProviderResult:
    provider: str  # "offline", "ip-api", "rdap", ...
    layer: str  # "L1", "L2", ...
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    skipped: str | None = None  # reason a provider did not run (no key, private IP, ...)
    cached: bool = False
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IPReport:
    input: str
    ip: str
    version: int
    lookup: dict[str, Any]
    results: list[ProviderResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)  # map pin, local time, agreement
    verdict: dict[str, Any] = field(default_factory=dict)  # scores etc. (Phase 6)

    def result(self, provider: str) -> ProviderResult | None:
        return next((r for r in self.results if r.provider == provider), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input": self.input,
            "ip": self.ip,
            "version": self.version,
            "lookup": self.lookup,
            "notes": self.notes,
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
            "verdict": self.verdict,
        }
