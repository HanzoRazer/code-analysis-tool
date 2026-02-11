"""Signal translator — converts raw findings into schema-aligned signal dicts.

Produces objects matching ``$defs/signal_snapshot`` in run_result.schema.json:
  - signal_id   (stable, derived from fingerprint)
  - type        (analyzer type string)
  - risk_level  (green / yellow / red)
  - urgency     (optional / recommended / important)
  - evidence    (finding_ids + primary_location)
  - i18n copy keys: title_key, summary_key, why_key, action.text_key
"""

from __future__ import annotations

from itertools import groupby
from operator import attrgetter

from code_audit.model import Severity, AnalyzerType
from code_audit.model.finding import Finding

# ── risk_level mapping ───────────────────────────────────────────────
_RISK_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.INFO: "green",
}

# ── urgency mapping ─────────────────────────────────────────────────
_URGENCY: dict[Severity, str] = {
    Severity.CRITICAL: "important",
    Severity.HIGH: "important",
    Severity.MEDIUM: "recommended",
    Severity.LOW: "optional",
    Severity.INFO: "optional",
}

# ── i18n copy key prefix by analyzer type ────────────────────────────
_COPY_PREFIX: dict[AnalyzerType, str] = {
    AnalyzerType.COMPLEXITY: "signal.complexity",
    AnalyzerType.EXCEPTIONS: "signal.exceptions",
    AnalyzerType.SECURITY: "signal.security",
    AnalyzerType.SAFETY: "signal.safety",
    AnalyzerType.GLOBAL_STATE: "signal.global_state",
    AnalyzerType.DEAD_CODE: "signal.dead_code",
}


def _worst_severity(findings: list[Finding]) -> Severity:
    """Return the highest severity from a group of findings."""
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    worst = Severity.INFO
    for f in findings:
        if order.index(f.severity) > order.index(worst):
            worst = f.severity
    return worst


def _group_key(f: Finding) -> str:
    """Group by rule_id if available, else by type."""
    if f.metadata and "rule_id" in f.metadata:
        return f.metadata["rule_id"]
    return f.type.value


def findings_to_signals(findings: list[Finding]) -> list[dict]:
    """Translate findings into schema-aligned signal snapshot dicts.

    Findings are grouped by rule_id so each signal aggregates related issues.
    """
    if not findings:
        return []

    signals: list[dict] = []
    sorted_findings = sorted(findings, key=_group_key)

    for rule_id, group_iter in groupby(sorted_findings, key=_group_key):
        group = list(group_iter)
        worst = _worst_severity(group)
        first = group[0]
        prefix = _COPY_PREFIX.get(first.type, f"signal.{first.type.value}")

        signal: dict = {
            "signal_id": f"sig_{first.fingerprint[:16]}",
            "type": first.type.value,
            "risk_level": _RISK_LEVEL.get(worst, "yellow"),
            "urgency": _URGENCY.get(worst, "recommended"),
            "title_key": f"{prefix}.{rule_id}.title",
            "summary_key": f"{prefix}.{rule_id}.summary",
            "why_key": f"{prefix}.{rule_id}.why",
            "action": {
                "text_key": f"{prefix}.{rule_id}.action",
                "urgency": _URGENCY.get(worst, "recommended"),
            },
            "evidence": {
                "finding_ids": [f.finding_id for f in group],
                "summary": {
                    "swallowed_count": sum(
                        1 for f in group
                        if (f.metadata or {}).get("rule_id") == "EXC_SWALLOW_001"
                    ),
                    "logged_count": sum(
                        1 for f in group
                        if (f.metadata or {}).get("rule_id") == "EXC_BROAD_LOGGED_001"
                    ),
                },
                "primary_location": {
                    "path": first.location.path,
                    "line_start": first.location.line_start,
                    "line_end": first.location.line_end,
                },
            },
        }
        signals.append(signal)

    return signals
