"""CLI entry-point for code_audit.

Usage:
    python -m code_audit <path>
    python -m code_audit <path> --json
    python -m code_audit <path> --project-id MY_PROJECT
    python -m code_audit scan --root <dir> --out <file>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from code_audit import __version__
from code_audit.analyzers.complexity import ComplexityAnalyzer
from code_audit.analyzers.exceptions import ExceptionsAnalyzer
from code_audit.core.runner import run_scan
from code_audit.run_result import build_run_result


# ── Vibe tier thresholds ─────────────────────────────────────────────
_GREEN = 75
_YELLOW = 55

_TIER_EMOJI = {"green": "🟢", "yellow": "🟡", "red": "🔴"}


def _tier_label(score: int) -> str:
    if score >= _GREEN:
        return "green"
    if score >= _YELLOW:
        return "yellow"
    return "red"


def _print_human(result_dict: dict) -> None:
    """Pretty-print a human-readable summary to stderr."""
    summary = result_dict.get("summary", {})
    score = summary.get("confidence_score", 0)
    tier = summary.get("risk_level", _tier_label(score))
    emoji = _TIER_EMOJI.get(tier, "⚪")
    total = summary.get("counts", {}).get("total", 0)

    print(f"\n{emoji}  Confidence: {score}/100  ({tier.upper()})", file=sys.stderr)
    print(f"   Findings : {total}", file=sys.stderr)

    by_sev = summary.get("counts", {}).get("by_severity", {})
    if by_sev:
        parts = [f"{k}={v}" for k, v in by_sev.items() if v]
        if parts:
            print(f"   Severity : {', '.join(parts)}", file=sys.stderr)

    signals = result_dict.get("signals_snapshot", [])
    red_signals = [s for s in signals if s.get("risk_level") == "red"]
    if red_signals:
        print(f"\n   🔴 {len(red_signals)} red signal(s) — fix before shipping:", file=sys.stderr)
        for s in red_signals[:5]:
            ev = s.get("evidence", {})
            loc = ev.get("primary_location", {})
            path = loc.get("path", "?")
            line = loc.get("line_start", "?")
            print(f"      • {s.get('type', '?')} → {path}:{line}", file=sys.stderr)
        if len(red_signals) > 5:
            print(f"      … and {len(red_signals) - 5} more", file=sys.stderr)

    print("", file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="code_audit",
        description="Scan Python files and emit a confidence score.",
    )
    sub = p.add_subparsers(dest="command")

    # ── default (positional path) mode ──────────────────────────────
    p.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=None,
        help="Root directory (or single .py file) to scan.",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
        help="Print the full RunResult JSON to stdout.",
    )
    p.add_argument(
        "--project-id",
        dest="project_id",
        default=None,
        help="Attach a project identifier to the run.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    # ── scan subcommand (functional pipeline) ───────────────────────
    scan_p = sub.add_parser(
        "scan",
        help="Run the functional dict-based pipeline.",
    )
    scan_p.add_argument(
        "--root",
        type=str,
        required=True,
        help="Root directory to scan.",
    )
    scan_p.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Path to write the RunResult JSON file.",
    )
    scan_p.add_argument(
        "--project-id",
        dest="project_id",
        default="",
        help="Attach a project identifier to the run.",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    """Entry-point — returns an exit code (0 = green, 1 = yellow, 2 = red)."""
    args = _build_parser().parse_args(argv)

    # ── scan subcommand (functional pipeline) ───────────────────────
    if args.command == "scan":
        result_dict = build_run_result(
            root=args.root,
            tool_version=__version__,
            project_id=args.project_id or "",
        )
        out_path: Path = args.out
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(result_dict, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        _print_human(result_dict)
        score = result_dict.get("summary", {}).get("confidence_score", 0)
        tier = _tier_label(score)
        return 0 if tier == "green" else (1 if tier == "yellow" else 2)

    # ── default positional-path mode (class-based pipeline) ─────────
    if args.path is None:
        print("error: please provide a path or use the 'scan' subcommand.", file=sys.stderr)
        return 2

    target: Path = args.path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Default analyzers
    analyzers = [ComplexityAnalyzer(), ExceptionsAnalyzer()]

    result = run_scan(
        root=target if target.is_dir() else target.parent,
        analyzers=analyzers,
        project_id=args.project_id or "",
    )

    result_dict = result.to_dict()

    # Always show human summary on stderr
    _print_human(result_dict)

    # Optionally dump full JSON to stdout (pipe-friendly)
    if args.json_out:
        json.dump(result_dict, sys.stdout, indent=2, default=str)
        print()  # trailing newline

    # Exit code mirrors tier
    score = result_dict.get("summary", {}).get("confidence_score", 0)
    tier = _tier_label(score)
    if tier == "green":
        return 0
    if tier == "yellow":
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
