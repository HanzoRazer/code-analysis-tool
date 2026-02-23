"""RunResult — the immutable, schema-aligned scan artifact."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from code_audit import __version__
from code_audit.model import RiskLevel
from code_audit.model.finding import Finding


@dataclass(slots=True)
class RunResult:
    """Assembled scan result matching ``run_result.schema.json``.

    Constructed by ``core.runner`` after all analyzers finish and the
    insight layer has produced signals.
    """

    # ── run metadata ────────────────────────────────────────────────
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    tool_version: str = __version__
    engine_version: str = "engine_v1"
    signal_logic_version: str = "signals_v2"
    openapi_classifier_version: str = "openapi_classifier_v1"  # version anchor: OpenAPI diff classifier logic
    bom_logic_version: str = "bom_v1"  # version anchor: BOM generation + consistency logic
    copy_version: str = "i18n@dev"

    config: dict = field(default_factory=dict)

    # ── summary ─────────────────────────────────────────────────────
    vibe_tier: RiskLevel = RiskLevel.GREEN
    confidence_score: int = 78
    findings: list[Finding] = field(default_factory=list)

    # ── signals (populated by insight layer) ────────────────────────
    signals_snapshot: list[dict] = field(default_factory=list)

    # ── artifacts ───────────────────────────────────────────────────
    snippet_policy: str = "truncated"

    # ── serialisation ───────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Produce the full RunResult JSON matching the schema."""
        severity_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity.value] = (
                severity_counts.get(f.severity.value, 0) + 1
            )
            type_counts[f.type.value] = type_counts.get(f.type.value, 0) + 1

        return {
            "schema_version": "run_result_v1",
            "run": {
                "run_id": self.run_id,
                "project_id": self.project_id or "",
                "created_at": self.created_at,
                "tool_version": self.tool_version,
                "engine_version": self.engine_version,
                "signal_logic_version": self.signal_logic_version,
                "copy_version": self.copy_version,
                "config": self.config,
            },
            "summary": {
                "vibe_tier": self.vibe_tier.value,
                "confidence_score": self.confidence_score,
                "counts": {
                    "findings_total": len(self.findings),
                    "by_severity": severity_counts,
                    "by_type": type_counts,
                },
            },
            "signals_snapshot": self.signals_snapshot,
            "findings_raw": [f.to_dict() for f in self.findings],
            "artifacts": {
                "redactions_applied": False,
                "snippet_policy": self.snippet_policy,
            },
        }
