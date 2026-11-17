"""Text-based dashboard — a terminal-friendly overview of project health.

Renders a compact summary table combining analyzer findings, debt snapshots,
and trend direction into a single view.  No external dependencies (no
Dash/Plotly) — pure stdlib, suitable for CI logs and ``less``.

For graphical dashboards, export JSON via :mod:`reports.exporters` and
consume with your preferred visualisation tool.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from code_audit.core.scan_integrity import degraded_coverage_lines
from code_audit.model import Severity
from code_audit.model.finding import Finding
from code_audit.model.run_result import RunResult

# ── severity ordering ─────────────────────────────────────────────────
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_TIER_EMOJI = {"green": "🟢", "yellow": "🟡", "red": "🔴", "inconclusive": "⚪"}
_SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def render_dashboard(
    result: RunResult,
    *,
    trend_direction: str = "",
    trend_delta: int = 0,
    width: int = 72,
) -> str:
    """Render a compact terminal dashboard from a ``RunResult``.

    Parameters
    ----------
    result:
        The scan result.
    trend_direction:
        Optional trend direction string (improving/worsening/stable).
    trend_delta:
        Optional change in total debt count vs previous snapshot.
    width:
        Maximum line width.

    Returns
    -------
    str
        Multiline text suitable for terminal display.
    """
    lines: list[str] = []
    tier = result.vibe_tier.value
    emoji = _TIER_EMOJI.get(tier, "⚪")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── header bar ──────────────────────────────────────────────────
    lines.append("═" * width)
    lines.append(f"  CODE AUDIT DASHBOARD  {emoji}  {tier.upper()}")
    lines.append("═" * width)
    shown = "inconclusive" if result.confidence_score is None else f"{result.confidence_score}/100"
    lines.append(f"  Score: {shown}    "
                 f"Findings: {len(result.findings)}    "
                 f"{now}")
    for line in degraded_coverage_lines(result.scan_integrity):
        lines.append(f"  {line}")
    if result.project_id:
        lines.append(f"  Project: {result.project_id}")
    lines.append("─" * width)

    # ── severity breakdown bar ──────────────────────────────────────
    sev_counts = Counter(f.severity for f in result.findings)
    total = len(result.findings)
    if total > 0:
        lines.append("  SEVERITY BREAKDOWN")
        bar_width = width - 20
        for sev in _SEVERITY_ORDER:
            count = sev_counts.get(sev, 0)
            if count == 0:
                continue
            pct = count / total
            bar_len = max(1, int(pct * bar_width))
            bar = "█" * bar_len
            e = _SEV_EMOJI.get(sev.value, " ")
            lines.append(
                f"  {e} {sev.value.upper():9s} {count:4d} {bar}"
            )
        lines.append("─" * width)

    # ── category breakdown ──────────────────────────────────────────
    type_counts = Counter(f.type for f in result.findings)
    if type_counts:
        lines.append("  CATEGORY BREAKDOWN")
        for atype, count in type_counts.most_common():
            lines.append(f"    {atype.value:20s} {count:4d}")
        lines.append("─" * width)

    # ── hotspot files ───────────────────────────────────────────────
    file_counts: Counter[str] = Counter(
        f.location.path for f in result.findings
    )
    if file_counts:
        lines.append("  FILE HOTSPOTS (top 5)")
        for path, count in file_counts.most_common(5):
            # Truncate long paths
            display = path if len(path) <= width - 15 else "…" + path[-(width - 16):]
            lines.append(f"    {display:>{width - 12}s} {count:4d}")
        lines.append("─" * width)

    # ── trend section ───────────────────────────────────────────────
    if trend_direction:
        direction_emoji = {
            "improving": "📉",
            "worsening": "📈",
            "stable": "➡️",
        }.get(trend_direction, "❓")
        sign = "+" if trend_delta > 0 else ""
        lines.append(
            f"  TREND: {direction_emoji} {trend_direction.upper()} "
            f"({sign}{trend_delta} items)"
        )
        lines.append("─" * width)

    # ── signal alerts ───────────────────────────────────────────────
    red_signals = [
        s for s in result.signals_snapshot if s.get("risk_level") == "red"
    ]
    if red_signals:
        lines.append(f"  🔴 {len(red_signals)} RED SIGNAL(S) — fix before shipping")
        for s in red_signals[:3]:
            lines.append(
                f"    • {s.get('type', '?')}: {s.get('headline', '')}"
            )
        if len(red_signals) > 3:
            lines.append(f"    … and {len(red_signals) - 3} more")
        lines.append("─" * width)

    # ── footer ──────────────────────────────────────────────────────
    lines.append(
        f"  code-audit {result.tool_version} "
        f"(engine {result.engine_version})"
    )
    lines.append("═" * width)

    return "\n".join(lines)
