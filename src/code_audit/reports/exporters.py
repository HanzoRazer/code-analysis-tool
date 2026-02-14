"""Multi-format exporters for scan results and findings.

Supports:

*  **JSON** — machine-readable, suitable for CI artifact storage.
*  **Markdown** — human-readable, suitable for PR comments.
*  **HTML** — self-contained HTML document with embedded CSS.

All exporters accept a :class:`RunResult` and produce a string.
"""

from __future__ import annotations

import html as html_mod
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from code_audit.model import Severity
from code_audit.utils.json_norm import stable_json_dumps
from code_audit.model.run_result import RunResult

# ── severity ordering (worst first) ─────────────────────────────────
_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


# ════════════════════════════════════════════════════════════════════
# JSON exporter
# ════════════════════════════════════════════════════════════════════


def export_json(result: RunResult, *, indent: int = 2) -> str:
    """Export a ``RunResult`` as indented JSON."""
    return stable_json_dumps(result.to_dict(), indent=indent)


# ════════════════════════════════════════════════════════════════════
# Markdown exporter
# ════════════════════════════════════════════════════════════════════


def export_markdown(result: RunResult, *, top_n: int = 20) -> str:
    """Export a ``RunResult`` as a concise Markdown summary.

    This is a lighter alternative to ``debt_report.render_markdown``
    — no git info, no signal snapshot, just the facts.
    """
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("# Scan Results")
    lines.append("")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Score:** {result.confidence_score}/100  ")
    lines.append(f"**Tier:** {result.vibe_tier.value.upper()}  ")
    lines.append(f"**Findings:** {len(result.findings)}")
    lines.append("")

    # Severity breakdown
    sev_counts = Counter(f.severity for f in result.findings)
    if sev_counts:
        lines.append("## By Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        for sev in _SEVERITY_ORDER:
            c = sev_counts.get(sev, 0)
            if c:
                lines.append(f"| {sev.value.upper()} | {c} |")
        lines.append("")

    # Top findings
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
            lines.append(
                f"{i}. **[{f.severity.value.upper()}]** `{loc}` — {f.message}"
            )
        lines.append("")

    lines.append("---")
    lines.append(f"*Exported by code-audit {result.tool_version}*")
    lines.append("")
    return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════
# HTML exporter
# ════════════════════════════════════════════════════════════════════

_SEVERITY_COLOR = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#17a2b8",
    "info": "#6c757d",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Code Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 2rem; color: #212529; }}
  h1 {{ color: #343a40; }}
  .summary {{ background: #f8f9fa; padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 0.85em; font-weight: 600; }}
  table {{ border-collapse: collapse; width: 100%%; margin-bottom: 1.5rem; }}
  th, td {{ text-align: left; padding: 6px 12px; border-bottom: 1px solid #dee2e6; }}
  th {{ background: #e9ecef; }}
  tr:hover {{ background: #f8f9fa; }}
  .finding {{ margin-bottom: 0.75rem; }}
  footer {{ margin-top: 2rem; color: #6c757d; font-size: 0.85em; }}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def export_html(result: RunResult, *, top_n: int = 30) -> str:
    """Export a ``RunResult`` as a self-contained HTML document."""
    parts: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tier = result.vibe_tier.value.upper()

    # Header
    parts.append("<h1>Code Audit Report</h1>")
    parts.append('<div class="summary">')
    parts.append(f"<p><strong>Generated:</strong> {now}</p>")
    parts.append(
        f"<p><strong>Score:</strong> {result.confidence_score}/100 "
        f"(<strong>{tier}</strong>)</p>"
    )
    parts.append(f"<p><strong>Findings:</strong> {len(result.findings)}</p>")
    if result.project_id:
        parts.append(
            f"<p><strong>Project:</strong> {html_mod.escape(result.project_id)}</p>"
        )
    parts.append("</div>")

    # Severity table
    sev_counts = Counter(f.severity for f in result.findings)
    if sev_counts:
        parts.append("<h2>Severity Breakdown</h2>")
        parts.append("<table><tr><th>Severity</th><th>Count</th></tr>")
        for sev in _SEVERITY_ORDER:
            c = sev_counts.get(sev, 0)
            if c:
                color = _SEVERITY_COLOR.get(sev.value, "#6c757d")
                parts.append(
                    f'<tr><td><span class="badge" style="background:{color}">'
                    f"{sev.value.upper()}</span></td><td>{c}</td></tr>"
                )
        parts.append("</table>")

    # Findings list
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (_SEVERITY_ORDER.index(f.severity), f.location.path),
    )
    top = sorted_findings[:top_n]
    if top:
        parts.append(f"<h2>Top {len(top)} Findings</h2>")
        for f in top:
            loc = f"{f.location.path}:{f.location.line_start}"
            color = _SEVERITY_COLOR.get(f.severity.value, "#6c757d")
            msg = html_mod.escape(f.message)
            parts.append(
                f'<div class="finding">'
                f'<span class="badge" style="background:{color}">'
                f"{f.severity.value.upper()}</span> "
                f"<code>{html_mod.escape(loc)}</code> &mdash; {msg}"
                f"</div>"
            )

    parts.append(
        f"<footer>Exported by code-audit {html_mod.escape(result.tool_version)}"
        f" &bull; {now}</footer>"
    )

    return _HTML_TEMPLATE.format(body="\n".join(parts))


# ════════════════════════════════════════════════════════════════════
# Dispatcher
# ════════════════════════════════════════════════════════════════════


def export_result(
    result: RunResult,
    fmt: str = "json",
    *,
    top_n: int = 20,
) -> str:
    """Export a ``RunResult`` in the specified format.

    Parameters
    ----------
    result:
        The scan result to export.
    fmt:
        One of ``"json"``, ``"markdown"``, ``"html"``.
    top_n:
        Number of top findings for markdown/html.

    Raises
    ------
    ValueError
        If *fmt* is not recognised.
    """
    if fmt == "json":
        return export_json(result)
    if fmt in ("markdown", "md"):
        return export_markdown(result, top_n=top_n)
    if fmt == "html":
        return export_html(result, top_n=top_n)
    raise ValueError(f"Unknown export format: {fmt!r} (use json|markdown|html)")
