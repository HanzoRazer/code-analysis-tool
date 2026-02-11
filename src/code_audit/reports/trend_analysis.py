"""Trend analysis — track how technical debt evolves over time.

Uses the debt-registry snapshot system to compute historical trends.
Given a :class:`DebtRegistry` directory with multiple snapshots, produces
trend data showing how debt count, composition, and churn change.

Outputs can be rendered as Markdown trend tables or JSON for dashboards.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from code_audit.model.debt_instance import DebtInstance, DebtType


# ── data structures ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SnapshotSummary:
    """Summary of one point-in-time snapshot."""

    name: str
    created_at: str
    total_items: int
    by_type: dict[str, int]


@dataclass(frozen=True, slots=True)
class TrendReport:
    """Historical trend across multiple snapshots."""

    snapshots: list[SnapshotSummary]
    direction: str          # "improving" | "worsening" | "stable" | "insufficient_data"
    delta: int              # latest total − earliest total
    peak: int               # max total across all snapshots
    trough: int             # min total across all snapshots


# ── snapshot loading ──────────────────────────────────────────────────


def _load_snapshot_meta(path: Path) -> dict[str, Any]:
    """Load snapshot JSON and extract metadata (without full deserialization)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return data


def load_trend_data(registry_dir: Path) -> list[SnapshotSummary]:
    """Load all snapshots from *registry_dir* and summarize them.

    Returns summaries sorted by ``created_at`` (chronological order).
    """
    if not registry_dir.exists():
        return []

    summaries: list[SnapshotSummary] = []
    for snap_path in sorted(registry_dir.glob("*.json")):
        if not snap_path.is_file():
            continue
        try:
            data = _load_snapshot_meta(snap_path)
        except (json.JSONDecodeError, OSError):
            continue

        items = data.get("items", [])
        by_type: dict[str, int] = Counter()
        for item in items:
            dt = item.get("debt_type", "unknown")
            by_type[dt] += 1

        summaries.append(
            SnapshotSummary(
                name=data.get("name", snap_path.stem),
                created_at=data.get("created_at", ""),
                total_items=data.get("debt_count", len(items)),
                by_type=dict(by_type),
            )
        )

    # Sort by created_at
    summaries.sort(key=lambda s: s.created_at)
    return summaries


def compute_trend(summaries: list[SnapshotSummary]) -> TrendReport:
    """Compute a :class:`TrendReport` from chronologically sorted summaries."""
    if len(summaries) < 2:
        return TrendReport(
            snapshots=summaries,
            direction="insufficient_data",
            delta=0,
            peak=summaries[0].total_items if summaries else 0,
            trough=summaries[0].total_items if summaries else 0,
        )

    totals = [s.total_items for s in summaries]
    delta = totals[-1] - totals[0]
    peak = max(totals)
    trough = min(totals)

    if delta < 0:
        direction = "improving"
    elif delta > 0:
        direction = "worsening"
    else:
        direction = "stable"

    return TrendReport(
        snapshots=summaries,
        direction=direction,
        delta=delta,
        peak=peak,
        trough=trough,
    )


# ── rendering ─────────────────────────────────────────────────────────

_DIRECTION_EMOJI = {
    "improving": "📉",
    "worsening": "📈",
    "stable": "➡️",
    "insufficient_data": "❓",
}


def render_trend_markdown(trend: TrendReport) -> str:
    """Render a :class:`TrendReport` as Markdown."""
    lines: list[str] = []
    emoji = _DIRECTION_EMOJI.get(trend.direction, "")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("# Technical Debt Trend Report")
    lines.append("")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Snapshots:** {len(trend.snapshots)}  ")
    lines.append(
        f"**Direction:** {emoji} {trend.direction.upper()} (delta: {trend.delta:+d})  "
    )
    lines.append(f"**Peak:** {trend.peak}  |  **Trough:** {trend.trough}")
    lines.append("")

    if not trend.snapshots:
        lines.append("_No snapshots found._")
        lines.append("")
        return "\n".join(lines)

    # ── timeline table ──────────────────────────────────────────────
    lines.append("## Timeline")
    lines.append("")
    lines.append("| Snapshot | Date | Total |")
    lines.append("|----------|------|------:|")
    for s in trend.snapshots:
        date = s.created_at[:10] if s.created_at else "?"
        lines.append(f"| {s.name} | {date} | {s.total_items} |")
    lines.append("")

    # ── debt-type breakdown (latest snapshot) ───────────────────────
    latest = trend.snapshots[-1]
    if latest.by_type:
        lines.append("## Current Composition (latest snapshot)")
        lines.append("")
        lines.append("| Debt Type | Count |")
        lines.append("|-----------|------:|")
        for dt, count in sorted(latest.by_type.items(), key=lambda x: -x[1]):
            lines.append(f"| {dt} | {count} |")
        lines.append("")

    # ── ASCII sparkline ─────────────────────────────────────────────
    if len(trend.snapshots) >= 2:
        lines.append("## Sparkline")
        lines.append("")
        lines.append("```")
        lines.append(_ascii_sparkline([s.total_items for s in trend.snapshots]))
        lines.append("```")
        lines.append("")

    # ── footer ──────────────────────────────────────────────────────
    lines.append("---")
    lines.append("*Report generated by code-audit trend analysis*")
    lines.append("")
    return "\n".join(lines)


def render_trend_json(trend: TrendReport) -> str:
    """Render a :class:`TrendReport` as JSON."""
    data = {
        "direction": trend.direction,
        "delta": trend.delta,
        "peak": trend.peak,
        "trough": trend.trough,
        "snapshots": [
            {
                "name": s.name,
                "created_at": s.created_at,
                "total_items": s.total_items,
                "by_type": s.by_type,
            }
            for s in trend.snapshots
        ],
    }
    return json.dumps(data, indent=2)


# ── helpers ───────────────────────────────────────────────────────────

_SPARK_CHARS = " ▁▂▃▄▅▆▇█"


def _ascii_sparkline(values: list[int]) -> str:
    """Produce a simple ASCII sparkline from a list of values."""
    if not values:
        return ""
    lo, hi = min(values), max(values)
    spread = hi - lo if hi != lo else 1
    return "".join(
        _SPARK_CHARS[min(int((v - lo) / spread * 8), 8)] for v in values
    )
