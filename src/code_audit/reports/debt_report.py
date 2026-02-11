"""Debt-report generator — consolidated markdown report of all findings.

Generalization of the luthiers-toolbox ``generate_debt_report.py``.

Runs the full analyzer suite via ``core.runner.run_scan()``, then renders a
Markdown document with:

*  Header with project metadata, git info, and timestamp.
*  Executive summary — vibe tier, confidence score, finding totals.
*  Severity breakdown table.
*  Category breakdown table (by AnalyzerType).
*  Top findings list (up to N worst items, configurable).
*  Per-file hotspot table (files with the most findings).
*  Signal snapshot (red / yellow signals).

The output is suitable for GitHub PR comments, CI artifacts, or standalone
consumption.
"""

from __future__ import annotations

import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from code_audit import __version__
from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding
from code_audit.model.run_result import RunResult


# ── severity ordering (worst first) ────────────────────────────────
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


# ── git helpers ────────────────────────────────────────────────────
def _git_info(root: Path) -> dict[str, str]:
    """Best-effort git commit hash and branch name."""
    info: dict[str, str] = {}
    try:
        info["commit"] = (
            subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=root,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
    except Exception:
        info["commit"] = "unknown"
    try:
        info["branch"] = (
            subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=root,
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )
    except Exception:
        info["branch"] = "unknown"
    return info


# ── tier emoji ─────────────────────────────────────────────────────
_TIER_EMOJI = {"green": "🟢", "yellow": "🟡", "red": "🔴"}


# ── core renderer ──────────────────────────────────────────────────
def render_markdown(
    result: RunResult,
    *,
    root: Path | None = None,
    top_n: int = 15,
    include_git: bool = True,
) -> str:
    """Render a ``RunResult`` as a Markdown debt report.

    Parameters
    ----------
    result:
        The scan result to render.
    root:
        Project root — used for git info and relative path display.
    top_n:
        Number of top findings to list (default 15).
    include_git:
        Whether to include git commit/branch info.

    Returns
    -------
    str
        Complete Markdown document.
    """
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tier = result.vibe_tier.value
    emoji = _TIER_EMOJI.get(tier, "⚪")

    # ── header ──────────────────────────────────────────────────────
    lines.append("# Technical Debt Report")
    lines.append("")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Tool version:** {result.tool_version}  ")
    if result.project_id:
        lines.append(f"**Project:** {result.project_id}  ")
    if include_git and root:
        git = _git_info(root)
        lines.append(f"**Branch:** `{git['branch']}`  ")
        lines.append(f"**Commit:** `{git['commit']}`  ")
    lines.append("")

    # ── executive summary ───────────────────────────────────────────
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"{emoji} **Confidence Score:** {result.confidence_score}/100 "
        f"(**{tier.upper()}**)"
    )
    lines.append(f"- **Total findings:** {len(result.findings)}")
    lines.append("")

    # ── severity breakdown ──────────────────────────────────────────
    sev_counts = Counter(f.severity for f in result.findings)
    if sev_counts:
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        for sev in _SEVERITY_ORDER:
            count = sev_counts.get(sev, 0)
            if count:
                lines.append(f"| {sev.value.upper()} | {count} |")
        lines.append("")

    # ── category breakdown ──────────────────────────────────────────
    type_counts = Counter(f.type for f in result.findings)
    if type_counts:
        lines.append("## Category Breakdown")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|----------|------:|")
        for atype, count in type_counts.most_common():
            lines.append(f"| {atype.value} | {count} |")
        lines.append("")

    # ── hotspot files ───────────────────────────────────────────────
    file_counts: Counter[str] = Counter(f.location.path for f in result.findings)
    if file_counts:
        lines.append("## File Hotspots")
        lines.append("")
        lines.append("| File | Findings |")
        lines.append("|------|--------:|")
        for path, count in file_counts.most_common(10):
            lines.append(f"| `{path}` | {count} |")
        lines.append("")

    # ── top findings ────────────────────────────────────────────────
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.location.path),
    )
    top = sorted_findings[:top_n]
    if top:
        lines.append(f"## Top {len(top)} Findings")
        lines.append("")
        for i, f in enumerate(top, 1):
            loc = f"{f.location.path}:{f.location.line_start}"
            rule = f.metadata.get("rule_id", f.type.value)
            lines.append(
                f"{i}. **[{f.severity.value.upper()}]** `{loc}` — "
                f"{f.message} ({rule})"
            )
        lines.append("")

    # ── signal snapshot ─────────────────────────────────────────────
    red_signals = [
        s for s in result.signals_snapshot if s.get("risk_level") == "red"
    ]
    yellow_signals = [
        s for s in result.signals_snapshot if s.get("risk_level") == "yellow"
    ]
    if red_signals or yellow_signals:
        lines.append("## Signals")
        lines.append("")
        if red_signals:
            lines.append(f"🔴 **{len(red_signals)} red signal(s)**")
            lines.append("")
            for s in red_signals:
                lines.append(f"- {s.get('type', '?')}: {s.get('headline', '')}")
            lines.append("")
        if yellow_signals:
            lines.append(f"🟡 **{len(yellow_signals)} yellow signal(s)**")
            lines.append("")
            for s in yellow_signals:
                lines.append(f"- {s.get('type', '?')}: {s.get('headline', '')}")
            lines.append("")

    # ── footer ──────────────────────────────────────────────────────
    lines.append("---")
    lines.append(
        f"*Report generated by code-audit {result.tool_version} "
        f"(engine {result.engine_version}, "
        f"signals {result.signal_logic_version})*"
    )
    lines.append("")

    return "\n".join(lines)


def generate_debt_report(
    root: Path,
    *,
    analyzers: list[Any] | None = None,
    project_id: str = "",
    top_n: int = 15,
    include_git: bool = True,
) -> str:
    """Run a full scan and produce a Markdown debt report.

    Parameters
    ----------
    root:
        Directory to scan.
    analyzers:
        Analyzer instances.  If *None* the default set is used.
    project_id:
        Project identifier for the report header.
    top_n:
        Number of top findings to include.
    include_git:
        Include git commit/branch info.

    Returns
    -------
    str
        Complete Markdown report.
    """
    from code_audit.analyzers.complexity import ComplexityAnalyzer
    from code_audit.analyzers.duplication import DuplicationAnalyzer
    from code_audit.analyzers.exceptions import ExceptionsAnalyzer
    from code_audit.analyzers.file_sizes import FileSizesAnalyzer
    from code_audit.contracts.safety_fence import SafetyFenceAnalyzer
    from code_audit.governance.import_ban import ImportBanAnalyzer
    from code_audit.core.runner import run_scan

    if analyzers is None:
        analyzers = [
            ComplexityAnalyzer(),
            DuplicationAnalyzer(),
            ExceptionsAnalyzer(),
            FileSizesAnalyzer(),
            ImportBanAnalyzer(),
            SafetyFenceAnalyzer(),
        ]

    result = run_scan(root, analyzers, project_id=project_id)
    return render_markdown(result, root=root, top_n=top_n, include_git=include_git)
