"""Monolithic run-result builder — functional pipeline.

``build_run_result()`` owns the full lifecycle:
  1. discover Python files
  2. run functional analyzers (dict-based)
  3. score confidence
  4. build signal snapshots
  5. assemble and return the schema-aligned run-result dict

This is the dict-based complement to the dataclass-based
``core.runner.run_scan`` pipeline; both produce output that
validates against ``schemas/run_result.schema.json``.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from .analyzers.exceptions import analyze_exceptions
from .contracts.load import validate_instance

Severity = Literal["info", "low", "medium", "high", "critical"]
RiskLevel = Literal["green", "yellow", "red"]
Urgency = Literal["optional", "recommended", "important"]


# ── helpers ──────────────────────────────────────────────────────────

def _stable_id(*parts: str) -> str:
    """Deterministic hash from pipe-joined *parts*."""
    h = hashlib.sha256()
    h.update("|".join(parts).encode("utf-8"))
    return h.hexdigest()


def _iter_python_files(root: Path) -> List[Path]:
    """
    MVP file discovery: walk the tree and collect *.py files.
    (We intentionally keep this simple until config/include/exclude is
    implemented.)
    """
    out: List[Path] = []
    for dp, _, fns in os.walk(root):
        parts = Path(dp).parts
        if any(
            p in {".venv", "venv", "__pycache__", "node_modules", ".git"}
            for p in parts
        ):
            continue
        for fn in fns:
            if fn.endswith(".py"):
                out.append(Path(dp) / fn)
    return out


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def _type_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for f in findings:
        t = f.get("type", "unknown")
        out[t] = out.get(t, 0) + 1
    return out


def _compute_confidence_and_vibe(
    findings: List[Dict[str, Any]],
) -> Tuple[int, RiskLevel]:
    """
    MVP confidence scoring:
      - Start at 100
      - High severity exceptions are a large penalty for beginners
    """
    score = 100
    vibe: RiskLevel = "green"

    for f in findings:
        if f.get("type") == "exceptions":
            rule_id = (f.get("metadata") or {}).get("rule_id")
            sev = f.get("severity")
            # Stronger penalty for "swallowed error" because it destroys feedback loops for beginners.
            if rule_id == "EXC_SWALLOW_001":
                if sev == "critical":
                    score -= 40
                elif sev == "high":
                    score -= 28
                else:
                    score -= 18
            # Logged broad exceptions still matter, but should not "panic" the user.
            elif rule_id == "EXC_BROAD_LOGGED_001":
                if sev == "medium":
                    score -= 8
                elif sev == "low":
                    score -= 4
                else:
                    score -= 10
            else:
                if sev == "critical":
                    score -= 35
                elif sev == "high":
                    score -= 25
                elif sev == "medium":
                    score -= 12
                elif sev == "low":
                    score -= 6

    score = max(0, min(100, score))

    has_exc = any(f.get("type") == "exceptions" for f in findings)
    has_high_exc = any(
        f.get("type") == "exceptions"
        and f.get("severity") in {"high", "critical"}
        for f in findings
    )
    if has_high_exc:
        vibe = "red"
    elif has_exc:
        vibe = "yellow"
    else:
        vibe = "green"

    return score, vibe


def _build_signals_snapshot(
    *,
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    MVP signal builder:
      - Create a single 'exceptions' signal if any exceptions findings exist.
      - Evidence: link to finding_ids and primary_location of the first finding.
    """
    exc_findings = [f for f in findings if f.get("type") == "exceptions"]
    exc_ids = [f["finding_id"] for f in exc_findings]
    if not exc_ids:
        return []

    # Prefer evidence ordering: swallowed errors first, then logged broad, then other broad.
    # This makes the "why" and "action" feel maximally relevant without changing copy keys.
    def _exc_priority(f: Dict[str, Any]) -> int:
        rule = (f.get("metadata") or {}).get("rule_id", "")
        if rule == "EXC_SWALLOW_001":
            return 0
        if rule == "EXC_BROAD_LOGGED_001":
            return 1
        return 2

    exc_sorted = sorted(exc_findings, key=_exc_priority)
    exc_ids_sorted = [f["finding_id"] for f in exc_sorted]

    first = exc_sorted[0]
    loc = first.get("location", {}) or {}
    primary_location = {
        "path": loc.get("path", ""),
        "line_start": loc.get("line_start", 1),
        "line_end": loc.get("line_end", 1),
    }

    severities = {f.get("severity") for f in exc_findings}
    if "critical" in severities or "high" in severities:
        risk: RiskLevel = "red"
        urgency: Urgency = "recommended"
    else:
        risk = "yellow"
        urgency = "recommended"

    # Evidence summary: small and stable, useful for UI chips/tooltips and experiments.
    swallowed_count = 0
    logged_count = 0
    for f in exc_findings:
        rule = (f.get("metadata") or {}).get("rule_id")
        if rule == "EXC_SWALLOW_001":
            swallowed_count += 1
        if rule == "EXC_BROAD_LOGGED_001":
            logged_count += 1

    signal_id = "sig_" + _stable_id("exceptions", *sorted(exc_ids))[:16]

    return [
        {
            "signal_id": signal_id,
            "type": "exceptions",
            "risk_level": risk,
            "urgency": urgency,
            "title_key": "signals.exceptions.title",
            "summary_key": "signals.exceptions.summary",
            "why_key": "signals.exceptions.why",
            "action": {
                "text_key": "signals.exceptions.action.text",
                "urgency": urgency,
            },
            "footer_key": "signals.exceptions.footer",
            "footer_icon_key": "signals.exceptions.footer_icon",
            "button_context": "exceptions",
            "evidence": {
                "finding_ids": exc_ids_sorted,
                "summary": {
                    "swallowed_count": swallowed_count,
                    "logged_count": logged_count,
                },
                "primary_location": primary_location,
            },
        }
    ]


# ── public entry point ───────────────────────────────────────────────

def build_run_result(
    *,
    root: str,
    tool_version: str,
    project_id: str = "",
    engine_version: str = "engine_v1",
    signal_logic_version: str = "signals_v1",
    copy_version: str = "i18n@dev",
    # Testing hooks for golden-fixture determinism
    _run_id: str | None = None,
    _created_at: str | None = None,
) -> Dict[str, Any]:
    """Build a complete run-result dict that validates against the schema.

    This is the **functional** pipeline entry point.  For the
    dataclass-based pipeline, use ``core.runner.run_scan`` instead.
    """
    root_path = Path(root).resolve()

    # 1) Raw findings (engine truth)
    findings_raw: List[Dict[str, Any]] = []
    for pyfile in _iter_python_files(root_path):
        findings_raw.extend(analyze_exceptions(pyfile, root=root_path))

    # 2) Snapshot signals (what the user saw at scan time)
    signals_snapshot = _build_signals_snapshot(findings=findings_raw)

    # 3) Confidence + vibe tier
    confidence_score, vibe_tier = _compute_confidence_and_vibe(findings_raw)

    summary = {
        "vibe_tier": vibe_tier,
        "confidence_score": confidence_score,
        "counts": {
            "findings_total": len(findings_raw),
            "by_severity": _severity_counts(findings_raw),
            "by_type": _type_counts(findings_raw),
        },
    }

    run: Dict[str, Any] = {
        "schema_version": "run_result_v1",
        "run": {
            "run_id": _run_id or str(uuid.uuid4()),
            "project_id": project_id,
            "created_at": _created_at or datetime.now(timezone.utc).isoformat(),
            "tool_version": tool_version,
            "engine_version": engine_version,
            "signal_logic_version": signal_logic_version,
            "copy_version": copy_version,
            "config": {
                "root": str(root_path),
            },
        },
        "summary": summary,
        "signals_snapshot": signals_snapshot,
        "findings_raw": findings_raw,
        "artifacts": {
            "redactions_applied": True,
            "snippet_policy": "truncated_200_chars",
            "note": "MVP: exceptions analyzer wired; more analyzers will be added incrementally.",
        },
    }

    # Runtime schema validation
    validate_instance(run, "run_result.schema.json")

    return run
