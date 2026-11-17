"""Fail-closed scan integrity.

The confidence scorer only sees findings. It cannot tell a clean repository
from one that was never actually scanned. This module is the pure decision
for that distinction: which analyzer outcomes count, when a scan is
assessable, and how a stored result without integrity evidence is treated.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

AnalyzerStatus = Literal[
    "ok",
    "not_applicable",
    "not_scheduled",
    "missing_capability",
    "failed",
]

# Only these statuses mean eligible code was not assessed.
_DEGRADING_STATUSES = frozenset({"missing_capability", "failed"})

# Analyzer ids whose failure means the scan cannot be assessed.
# Mirrors the runner hard-stop set (security / safety / exceptions).
CRITICAL_ANALYZER_IDS = frozenset({"security", "exceptions", "safety", "safety_fence"})


class MissingAnalyzerCapability(Exception):
    """An analyzer had eligible files but its parser or dependency is absent."""

    def __init__(self, analyzer_id: str) -> None:
        super().__init__(analyzer_id)
        self.analyzer_id = analyzer_id


@dataclass(frozen=True, slots=True)
class AnalyzerOutcome:
    analyzer_id: str
    status: AnalyzerStatus
    is_critical: bool
    duration_s: float | None = None

    def to_dict(self) -> dict[str, Any]:
        # Duration is process-local. The artifact keeps the key and a null
        # value so golden output does not depend on wall-clock time.
        return {
            "analyzer_id": self.analyzer_id,
            "status": self.status,
            "is_critical": self.is_critical,
            "duration_s": None,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AnalyzerOutcome:
        return cls(
            analyzer_id=str(payload["analyzer_id"]),
            status=payload["status"],
            is_critical=bool(payload["is_critical"]),
            duration_s=payload.get("duration_s"),
        )


@dataclass(frozen=True, slots=True)
class ScanIntegrity:
    assessable: bool
    files_scanned: int
    analyzers_total: int
    analyzers_ok: int
    degraded: list[AnalyzerOutcome]
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessable": self.assessable,
            "files_scanned": self.files_scanned,
            "analyzers_total": self.analyzers_total,
            "analyzers_ok": self.analyzers_ok,
            "degraded": [item.to_dict() for item in self.degraded],
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> ScanIntegrity:
        degraded_raw = payload.get("degraded") or []
        return cls(
            assessable=bool(payload["assessable"]),
            files_scanned=int(payload["files_scanned"]),
            analyzers_total=int(payload["analyzers_total"]),
            analyzers_ok=int(payload["analyzers_ok"]),
            degraded=[AnalyzerOutcome.from_dict(item) for item in degraded_raw],
            reasons=[str(item) for item in (payload.get("reasons") or [])],
        )


def evaluate_scan_integrity(
    files_scanned: int,
    outcomes: list[AnalyzerOutcome],
) -> ScanIntegrity:
    """Apply D3–D5. Pure and deterministic.

    Not assessable when no source files were discovered, no analyzer
    completed, or a critical analyzer is ``missing_capability`` or ``failed``.
    ``not_applicable`` and ``not_scheduled`` never degrade. Other degrading
    outcomes stay assessable and are listed for the GREEN→YELLOW cap.
    """
    degraded = [item for item in outcomes if item.status in _DEGRADING_STATUSES]
    analyzers_ok = sum(1 for item in outcomes if item.status == "ok")

    blocking: list[str] = []
    if files_scanned == 0:
        blocking.append("no_source_files")
    if analyzers_ok == 0:
        blocking.append("no_analyzer_completed")
    for item in degraded:
        if item.is_critical:
            blocking.append(f"critical_analyzer_{item.status}:{item.analyzer_id}")

    reasons = list(blocking)
    if degraded and not blocking:
        reasons.append("noncritical_degradation")

    return ScanIntegrity(
        assessable=not blocking,
        files_scanned=files_scanned,
        analyzers_total=len(outcomes),
        analyzers_ok=analyzers_ok,
        degraded=degraded,
        reasons=reasons,
    )


@dataclass(frozen=True, slots=True)
class StoredResultView:
    """How an updated consumer reads a stored run result (D7)."""

    verified: bool
    effective_tier: str
    integrity: ScanIntegrity | None


def interpret_stored_result(payload: dict[str, Any]) -> StoredResultView:
    """A result with no ``scan_integrity`` block is unverified.

    Claimed GREEN is never trusted in that case. A claimed yellow or red
    tier is kept (it is not a pass) but still marked unverified.
    """
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    claimed = str(summary.get("vibe_tier") or "green")
    raw = payload.get("scan_integrity")
    if not isinstance(raw, dict):
        effective = "inconclusive" if claimed == "green" else claimed
        return StoredResultView(verified=False, effective_tier=effective, integrity=None)

    integrity = ScanIntegrity.from_dict(raw)
    effective = claimed
    if not integrity.assessable and claimed != "red":
        effective = "inconclusive"
    elif integrity.degraded and claimed == "green":
        effective = "yellow"
    return StoredResultView(verified=True, effective_tier=effective, integrity=integrity)


def degraded_coverage_lines(integrity: dict[str, Any] | None) -> list[str]:
    """Human lines disclosing incomplete coverage. Empty when nothing degraded."""
    degraded = (integrity or {}).get("degraded") or []
    if not degraded:
        return []
    lines = ["Incomplete coverage (degraded analyzers):"]
    for item in degraded:
        analyzer_id = item.get("analyzer_id", "?")
        status = item.get("status", "?")
        lines.append(f"• {analyzer_id} — {status}")
    return lines
