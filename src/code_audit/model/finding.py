"""Finding — the normalized engine output for a single detected issue."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import AnalyzerType, Severity


@dataclass(frozen=True, slots=True)
class Location:
    """Source-code location for a finding."""

    path: str
    line_start: int
    line_end: int


@dataclass(frozen=True, slots=True)
class Finding:
    """Immutable, schema-aligned engine finding.

    Corresponds to ``findings_raw[]`` in ``run_result.schema.json``.
    """

    finding_id: str
    type: AnalyzerType
    severity: Severity
    confidence: float          # 0.0 – 1.0
    message: str
    location: Location
    fingerprint: str
    snippet: str = ""
    metadata: dict = field(default_factory=dict)

    # ── serialisation ───────────────────────────────────────────────

    def to_dict(self) -> dict:
        d: dict = {
            "finding_id": self.finding_id,
            "type": self.type.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "message": self.message,
            "location": {
                "path": self.location.path,
                "line_start": self.location.line_start,
                "line_end": self.location.line_end,
            },
            "fingerprint": self.fingerprint,
        }
        if self.snippet:
            d["snippet"] = self.snippet
        if self.metadata:
            d["metadata"] = dict(self.metadata)
        return d


def make_fingerprint(
    rule_id: str,
    rel_path: str,
    symbol: str,
    snippet: str,
) -> str:
    """Deterministic finding fingerprint per spec: sha256(rule|path|symbol|snippet)."""
    # Normalize path separators for cross-platform stability
    rel_path = rel_path.replace("\\", "/")
    payload = "|".join([rule_id, rel_path, symbol, snippet.strip()])
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
