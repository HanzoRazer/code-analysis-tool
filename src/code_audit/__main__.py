"""CLI entry-point for code_audit.

Usage:
    python -m code_audit <path>
    python -m code_audit <path> --json
    python -m code_audit <path> --project-id MY_PROJECT
    python -m code_audit scan --root <dir> --out <dir> [--emit-signals signals_latest.json]
    python -m code_audit validate <instance.json> <schema_name>
    python -m code_audit fence check <path> [--patterns PAT ...] [--json]
    python -m code_audit fence list
    python -m code_audit governance deprecation <path> [--registry FILE] [--warn-only] [--upcoming N]
    python -m code_audit governance import-ban <path> [--patterns PAT ...]
    python -m code_audit governance legacy-usage <path> [--routes FILE] [--budget N]
    python -m code_audit report <path> [--format markdown] [--output FILE] [--top N]
    python -m code_audit debt scan <path> [--json]
    python -m code_audit debt plan <path> [--output FILE]
    python -m code_audit debt snapshot <path> --name <NAME> [--registry-dir DIR]
    python -m code_audit debt compare <path> --baseline <NAME> [--registry-dir DIR]
    python -m code_audit inventory <path> [--patterns PAT ...] [--json]
    python -m code_audit sdk-boundary <path> [--api-prefix PREFIX ...] [--allow GLOB ...] [--json]
    python -m code_audit truth-map <markdown-file> [--json]
    python -m code_audit trend [--registry-dir DIR] [--format markdown|json] [--output FILE]
    python -m code_audit export <path> [--format json|markdown|html] [--output FILE] [--top N]
    python -m code_audit dashboard <path> [--registry-dir DIR] [--width N]
    python -m code_audit predict <path> [--top N] [--json]
    python -m code_audit cluster <path> [--k N] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from code_audit import __version__
from code_audit.analyzers.complexity import ComplexityAnalyzer
from code_audit.analyzers.duplication import DuplicationAnalyzer
from code_audit.analyzers.exceptions import ExceptionsAnalyzer
from code_audit.analyzers.file_sizes import FileSizesAnalyzer
from code_audit.contracts.load import validate_file
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


def _exit_code_from_score(score: int) -> int:
    """0 = green (≥75), 1 = yellow (55-74), 2 = red (<55)."""
    if score >= _GREEN:
        return 0
    if score >= _YELLOW:
        return 1
    return 2


def _print_human(result_dict: dict) -> None:
    """Pretty-print a human-readable summary to stderr."""
    summary = result_dict.get("summary", {})
    score = summary.get("confidence_score", 0)
    tier = summary.get("vibe_tier", _tier_label(score))
    emoji = _TIER_EMOJI.get(tier, "⚪")
    total = summary.get("counts", {}).get("findings_total", 0)

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
        prog="code-audit",
        description="Confidence engine for beginner Vibe Coders.",
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
    p.add_argument("--max-file-lines", type=int, default=400)
    p.add_argument("--max-func-lines", type=int, default=60)

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
    scan_p.add_argument(
        "--emit-signals",
        dest="emit_signals",
        metavar="REL_PATH",
        default=None,
        help="Also emit signals_latest.json at this relative path inside --out dir.",
    )
    scan_p.add_argument("--max-file-lines", type=int, default=400)
    scan_p.add_argument("--max-func-lines", type=int, default=60)

    # ── validate subcommand ─────────────────────────────────────────
    val_p = sub.add_parser(
        "validate",
        help="Validate a JSON instance against a bundled schema.",
    )
    val_p.add_argument("instance", type=Path, help="Path to the JSON file to validate.")
    val_p.add_argument("schema_name", help="Schema filename, e.g. run_result.schema.json")

    # ── fence subcommand ────────────────────────────────────────────
    fence_p = sub.add_parser(
        "fence",
        help="Safety & architecture fence checks.",
    )
    fence_sub = fence_p.add_subparsers(dest="fence_command")

    # fence check
    fence_check_p = fence_sub.add_parser(
        "check",
        help="Run safety fence checks against a codebase.",
    )
    fence_check_p.add_argument(
        "path",
        type=Path,
        help="Root directory to check.",
    )
    fence_check_p.add_argument(
        "--patterns",
        nargs="*",
        default=None,
        help="Safety function name patterns (regex). Overrides built-in defaults.",
    )
    fence_check_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
        help="Print findings as JSON to stdout.",
    )

    # fence list
    fence_sub.add_parser(
        "list",
        help="List all registered fence definitions.",
    )

    # ── governance subcommand ───────────────────────────────────────
    gov_p = sub.add_parser(
        "governance",
        help="Governance gates: deprecation, import-ban, legacy-usage.",
    )
    gov_sub = gov_p.add_subparsers(dest="gov_command")

    # governance deprecation
    gov_dep_p = gov_sub.add_parser(
        "deprecation",
        help="Check for overdue / upcoming deprecation sunsets.",
    )
    gov_dep_p.add_argument("gov_path", type=Path, help="Root directory to check.")
    gov_dep_p.add_argument(
        "--registry",
        type=Path,
        default=None,
        help="Path to deprecation_registry.json (default: <root>/deprecation_registry.json).",
    )
    gov_dep_p.add_argument(
        "--warn-only",
        action="store_true",
        default=False,
        help="Emit overdue findings as MEDIUM instead of HIGH.",
    )
    gov_dep_p.add_argument(
        "--upcoming",
        type=int,
        default=30,
        help="Days ahead to warn about upcoming sunsets (default: 30, 0=disable).",
    )
    gov_dep_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # governance import-ban
    gov_ib_p = gov_sub.add_parser(
        "import-ban",
        help="Scan for banned import patterns.",
    )
    gov_ib_p.add_argument("gov_path", type=Path, help="Root directory to check.")
    gov_ib_p.add_argument(
        "--patterns",
        nargs="*",
        default=None,
        help="Regex patterns for banned imports (default: app._experimental.ai_core).",
    )
    gov_ib_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # governance legacy-usage
    gov_lu_p = gov_sub.add_parser(
        "legacy-usage",
        help="Detect frontend references to legacy API endpoints.",
    )
    gov_lu_p.add_argument("gov_path", type=Path, help="Root directory to check.")
    gov_lu_p.add_argument(
        "--routes",
        type=Path,
        default=None,
        help="JSON file with legacy route patterns.",
    )
    gov_lu_p.add_argument(
        "--budget",
        type=int,
        default=None,
        help="Max allowed matches before severity escalates (default: no budget).",
    )
    gov_lu_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # ── report subcommand ───────────────────────────────────────────
    report_p = sub.add_parser(
        "report",
        help="Generate a consolidated technical-debt report.",
    )
    report_p.add_argument(
        "report_path",
        type=Path,
        help="Root directory to scan.",
    )
    report_p.add_argument(
        "--format",
        dest="report_format",
        choices=["markdown"],
        default="markdown",
        help="Report format (default: markdown).",
    )
    report_p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write report to FILE instead of stdout.",
    )
    report_p.add_argument(
        "--project-id",
        dest="report_project_id",
        default="",
        help="Project identifier for the report header.",
    )
    report_p.add_argument(
        "--top",
        type=int,
        default=15,
        help="Number of top findings to include (default: 15).",
    )
    report_p.add_argument(
        "--no-git",
        dest="no_git",
        action="store_true",
        default=False,
        help="Omit git commit/branch info from the report.",
    )

    # ── inventory subcommand (Feature Hunt) ──────────────────────────
    inv_p = sub.add_parser(
        "inventory",
        help="Scan for feature-flag usage patterns in source code.",
    )
    inv_p.add_argument(
        "inv_path",
        type=Path,
        help="Root directory to scan.",
    )
    inv_p.add_argument(
        "--patterns",
        nargs="*",
        default=None,
        help="Extra regex patterns to hunt for (regex,label pairs).",
    )
    inv_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # ── sdk-boundary subcommand ──────────────────────────────────────
    sdk_p = sub.add_parser(
        "sdk-boundary",
        help="Detect frontend code bypassing the SDK layer with direct API calls.",
    )
    sdk_p.add_argument(
        "sdk_path",
        type=Path,
        help="Root directory to scan.",
    )
    sdk_p.add_argument(
        "--api-prefix",
        nargs="*",
        default=None,
        dest="api_prefixes",
        help="API path prefixes to detect (default: /api/).",
    )
    sdk_p.add_argument(
        "--allow",
        nargs="*",
        default=None,
        dest="allowed_files",
        help="Glob patterns for files allowed to make direct calls (e.g. SDK itself).",
    )
    sdk_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # ── truth-map subcommand ─────────────────────────────────────────
    tm_p = sub.add_parser(
        "truth-map",
        help="Parse an ENDPOINT_TRUTH_MAP.md and display or validate endpoints.",
    )
    tm_p.add_argument(
        "truth_map_file",
        type=Path,
        help="Path to the Markdown truth-map file.",
    )
    tm_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
        help="Output parsed endpoints as JSON.",
    )

    # ── debt subcommand (Strangler Fig) ──────────────────────────────
    debt_p = sub.add_parser(
        "debt",
        help="Strangler Fig: detect structural debt, generate plans, track progress.",
    )
    debt_sub = debt_p.add_subparsers(dest="debt_command")

    # debt scan
    debt_scan_p = debt_sub.add_parser(
        "scan",
        help="Scan for structural technical debt (God Class, God Function, etc.).",
    )
    debt_scan_p.add_argument("debt_path", type=Path, help="Root directory to scan.")
    debt_scan_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # debt plan
    debt_plan_p = debt_sub.add_parser(
        "plan",
        help="Generate a prioritised refactoring plan.",
    )
    debt_plan_p.add_argument("debt_path", type=Path, help="Root directory to scan.")
    debt_plan_p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write plan to FILE instead of stdout.",
    )
    debt_plan_p.add_argument(
        "--project-id",
        dest="debt_project_id",
        default="",
    )

    # debt snapshot
    debt_snap_p = debt_sub.add_parser(
        "snapshot",
        help="Save a named debt snapshot for later comparison.",
    )
    debt_snap_p.add_argument("debt_path", type=Path, help="Root directory to scan.")
    debt_snap_p.add_argument(
        "--name",
        required=True,
        help="Snapshot name (e.g. 'baseline', 'sprint-42').",
    )
    debt_snap_p.add_argument(
        "--registry-dir",
        dest="registry_dir",
        type=Path,
        default=None,
        help="Directory for snapshot files (default: <root>/.debt_snapshots).",
    )

    # debt compare
    debt_cmp_p = debt_sub.add_parser(
        "compare",
        help="Compare current debt against a saved baseline snapshot.",
    )
    debt_cmp_p.add_argument("debt_path", type=Path, help="Root directory to scan.")
    debt_cmp_p.add_argument(
        "--baseline",
        required=True,
        help="Name of the baseline snapshot to compare against.",
    )
    debt_cmp_p.add_argument(
        "--registry-dir",
        dest="registry_dir",
        type=Path,
        default=None,
        help="Directory for snapshot files (default: <root>/.debt_snapshots).",
    )
    debt_cmp_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # ── trend subcommand (Trend Analysis) ────────────────────────────
    trend_p = sub.add_parser(
        "trend",
        help="Analyse historical debt trends from registry snapshots.",
    )
    trend_p.add_argument(
        "--registry-dir",
        dest="trend_registry_dir",
        type=Path,
        default=None,
        help="Directory containing debt snapshots (default: .debt_snapshots).",
    )
    trend_p.add_argument(
        "--format",
        dest="trend_format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    trend_p.add_argument(
        "--output",
        dest="trend_output",
        type=Path,
        default=None,
        help="Write trend output to FILE instead of stdout.",
    )

    # ── export subcommand (Multi-format export) ──────────────────────
    export_p = sub.add_parser(
        "export",
        help="Export scan results in JSON, Markdown, or HTML format.",
    )
    export_p.add_argument(
        "export_path",
        type=Path,
        help="Root directory to scan.",
    )
    export_p.add_argument(
        "--format",
        dest="export_format",
        choices=["json", "markdown", "md", "html"],
        default="json",
        help="Export format (default: json).",
    )
    export_p.add_argument(
        "--output",
        dest="export_output",
        type=Path,
        default=None,
        help="Write export to FILE instead of stdout.",
    )
    export_p.add_argument(
        "--top",
        dest="export_top",
        type=int,
        default=20,
        help="Number of top findings to include (default: 20).",
    )

    # ── dashboard subcommand ─────────────────────────────────────────
    dash_p = sub.add_parser(
        "dashboard",
        help="Show a terminal-friendly project health dashboard.",
    )
    dash_p.add_argument(
        "dash_path",
        type=Path,
        help="Root directory to scan.",
    )
    dash_p.add_argument(
        "--registry-dir",
        dest="dash_registry_dir",
        type=Path,
        default=None,
        help="Directory containing debt snapshots (for trend data).",
    )
    dash_p.add_argument(
        "--width",
        dest="dash_width",
        type=int,
        default=72,
        help="Terminal width for dashboard layout (default: 72).",
    )

    # ── predict subcommand (Bug Predictor) ───────────────────────────
    predict_p = sub.add_parser(
        "predict",
        help="Predict bug probability per file using heuristic scoring.",
    )
    predict_p.add_argument(
        "predict_path",
        type=Path,
        help="Root directory to scan.",
    )
    predict_p.add_argument(
        "--top",
        dest="predict_top",
        type=int,
        default=10,
        help="Number of top risky files to show (default: 10).",
    )
    predict_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    # ── cluster subcommand (Code Clustering) ─────────────────────────
    cluster_p = sub.add_parser(
        "cluster",
        help="Group files by structural similarity using k-means clustering.",
    )
    cluster_p.add_argument(
        "cluster_path",
        type=Path,
        help="Root directory to scan.",
    )
    cluster_p.add_argument(
        "--k",
        dest="cluster_k",
        default="auto",
        help="Number of clusters (integer or 'auto'; default: auto).",
    )
    cluster_p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        default=False,
    )

    return p


def _handle_fence(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit fence check|list``."""
    from code_audit.contracts.fence_registry import FenceRegistry
    from code_audit.contracts.safety_fence import SafetyFenceAnalyzer
    from code_audit.core.discover import discover_py_files

    if args.fence_command == "list":
        registry = FenceRegistry()
        for fence in registry.list():
            status = "ON" if fence.enabled else "OFF"
            print(f"[{status}]  {fence.fence_id:16s}  {fence.name}  ({fence.level.value})")
        return 0

    if args.fence_command == "check":
        target: Path = args.path.resolve()
        if not target.exists():
            print(f"error: path does not exist: {target}", file=sys.stderr)
            return 2

        analyzer = SafetyFenceAnalyzer(
            safety_patterns=args.patterns,
        )
        files = discover_py_files(target)
        findings = analyzer.run(target, files)

        if getattr(args, "json_out", False):
            json.dump(
                [f.to_dict() for f in findings],
                sys.stdout,
                indent=2,
                default=str,
            )
            print()
        else:
            if not findings:
                print("No fence violations found.", file=sys.stderr)
            else:
                print(
                    f"\n  {len(findings)} fence violation(s):\n",
                    file=sys.stderr,
                )
                for f in findings:
                    sev = f.severity.value.upper()
                    loc = f"{f.location.path}:{f.location.line_start}"
                    print(f"    [{sev}]  {loc}  {f.message}", file=sys.stderr)
                print("", file=sys.stderr)

        # Exit code: 0 = clean, 1 = violations found
        return 1 if findings else 0

    # No subcommand given
    print("error: use 'fence check' or 'fence list'.", file=sys.stderr)
    return 2


def _handle_governance(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit governance deprecation|import-ban|legacy-usage``."""
    from code_audit.core.discover import discover_py_files

    if args.gov_command == "deprecation":
        from code_audit.governance.deprecation import DeprecationAnalyzer

        target: Path = args.gov_path.resolve()
        if not target.exists():
            print(f"error: path does not exist: {target}", file=sys.stderr)
            return 2

        analyzer = DeprecationAnalyzer(
            registry_path=args.registry,
            warn_only=args.warn_only,
            upcoming_days=args.upcoming,
        )
        files = discover_py_files(target)
        findings = analyzer.run(target, files)

    elif args.gov_command == "import-ban":
        from code_audit.governance.import_ban import ImportBanAnalyzer

        target = args.gov_path.resolve()
        if not target.exists():
            print(f"error: path does not exist: {target}", file=sys.stderr)
            return 2

        analyzer = ImportBanAnalyzer(banned_patterns=args.patterns)
        files = discover_py_files(target)
        findings = analyzer.run(target, files)

    elif args.gov_command == "legacy-usage":
        from code_audit.governance.legacy_usage import LegacyUsageAnalyzer

        target = args.gov_path.resolve()
        if not target.exists():
            print(f"error: path does not exist: {target}", file=sys.stderr)
            return 2

        analyzer = LegacyUsageAnalyzer(
            legacy_routes=args.routes,
            budget=args.budget,
        )
        # Legacy usage scans all files (not just .py)
        all_files = [
            p for p in target.rglob("*") if p.is_file() and not p.name.startswith(".")
        ]
        findings = analyzer.run(target, all_files)

    else:
        print(
            "error: use 'governance deprecation', 'governance import-ban', "
            "or 'governance legacy-usage'.",
            file=sys.stderr,
        )
        return 2

    # Output
    if getattr(args, "json_out", False):
        json.dump(
            [f.to_dict() for f in findings],
            sys.stdout,
            indent=2,
            default=str,
        )
        print()
    else:
        if not findings:
            print("No governance violations found.", file=sys.stderr)
        else:
            print(
                f"\n  {len(findings)} governance violation(s):\n",
                file=sys.stderr,
            )
            for f in findings:
                sev = f.severity.value.upper()
                loc = f"{f.location.path}:{f.location.line_start}"
                print(f"    [{sev}]  {loc}  {f.message}", file=sys.stderr)
            print("", file=sys.stderr)

    return 1 if findings else 0


def _handle_report(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit report <path>``."""
    from code_audit.reports.debt_report import generate_debt_report

    target: Path = args.report_path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    report = generate_debt_report(
        target,
        project_id=getattr(args, "report_project_id", "") or "",
        top_n=args.top,
        include_git=not args.no_git,
    )

    if args.output:
        out: Path = args.output
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(report, encoding="utf-8")
        print(f"Report written to {out}", file=sys.stderr)
    else:
        print(report)

    return 0


def _handle_inventory(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit inventory <path>``."""
    from code_audit.core.discover import discover_py_files
    from code_audit.inventory.feature_hunt import FeatureHuntAnalyzer

    target: Path = args.inv_path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Parse extra patterns from CLI if provided
    extra: list[tuple[str, str]] | None = None
    if args.patterns:
        extra = []
        for pat in args.patterns:
            if "," in pat:
                regex, label = pat.split(",", 1)
                extra.append((regex, label))
            else:
                extra.append((pat, "custom"))

    analyzer = FeatureHuntAnalyzer(extra_patterns=extra)
    # Scan all source files (not just .py) for feature flags
    all_files = [
        p for p in target.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    ]
    findings = analyzer.run(target, all_files)

    if getattr(args, "json_out", False):
        json.dump(
            [f.to_dict() for f in findings],
            sys.stdout,
            indent=2,
            default=str,
        )
        print()
    else:
        if not findings:
            print("No feature flag references found.", file=sys.stderr)
        else:
            print(
                f"\n  {len(findings)} feature flag reference(s) found:\n",
                file=sys.stderr,
            )
            for f in findings:
                loc = f"{f.location.path}:{f.location.line_start}"
                label = f.metadata.get("pattern_label", "")
                print(f"    [{label}]  {loc}  {f.message}", file=sys.stderr)
            print("", file=sys.stderr)

    return 1 if findings else 0


def _handle_sdk_boundary(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit sdk-boundary <path>``."""
    from code_audit.governance.sdk_boundary import SdkBoundaryAnalyzer

    target: Path = args.sdk_path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    analyzer = SdkBoundaryAnalyzer(
        api_prefixes=args.api_prefixes,
        allowed_files=args.allowed_files,
    )
    # Scan all files (frontend-focused extensions handled inside analyzer)
    all_files = [
        p for p in target.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    ]
    findings = analyzer.run(target, all_files)

    if getattr(args, "json_out", False):
        json.dump(
            [f.to_dict() for f in findings],
            sys.stdout,
            indent=2,
            default=str,
        )
        print()
    else:
        if not findings:
            print("No SDK boundary violations found.", file=sys.stderr)
        else:
            print(
                f"\n  {len(findings)} SDK boundary violation(s):\n",
                file=sys.stderr,
            )
            for f in findings:
                sev = f.severity.value.upper()
                loc = f"{f.location.path}:{f.location.line_start}"
                print(f"    [{sev}]  {loc}  {f.message}", file=sys.stderr)
            print("", file=sys.stderr)

    return 1 if findings else 0


def _handle_truth_map(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit truth-map <file>``."""
    from code_audit.utils.parse_truth_map import parse_truth_map

    target: Path = args.truth_map_file.resolve()
    if not target.exists():
        print(f"error: file does not exist: {target}", file=sys.stderr)
        return 2

    try:
        entries = parse_truth_map(target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if getattr(args, "json_out", False):
        json.dump(
            [e.to_dict() for e in entries],
            sys.stdout,
            indent=2,
        )
        print()
    else:
        if not entries:
            print("No endpoints found in truth map.", file=sys.stderr)
        else:
            print(
                f"\n  {len(entries)} endpoint(s) in truth map:\n",
                file=sys.stderr,
            )
            for e in entries:
                status_tag = f" [{e.status}]" if e.status != "active" else ""
                print(
                    f"    {e.method:6s} {e.path}{status_tag}",
                    file=sys.stderr,
                )
            print("", file=sys.stderr)

    return 0


def _handle_trend(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit trend``."""
    from code_audit.reports.trend_analysis import (
        compute_trend,
        load_trend_data,
        render_trend_json,
        render_trend_markdown,
    )

    reg_dir = args.trend_registry_dir or Path(".debt_snapshots")
    if not reg_dir.exists():
        print(f"error: registry directory does not exist: {reg_dir}", file=sys.stderr)
        return 2

    summaries = load_trend_data(reg_dir)
    trend = compute_trend(summaries)

    if args.trend_format == "json":
        output = render_trend_json(trend)
    else:
        output = render_trend_markdown(trend)

    if args.trend_output:
        out: Path = args.trend_output
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        print(f"Trend report written to {out}", file=sys.stderr)
    else:
        print(output)

    return 0


def _handle_export(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit export <path>``."""
    from code_audit.reports.exporters import export_result

    target: Path = args.export_path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Run a scan to get RunResult
    analyzers = [
        ComplexityAnalyzer(),
        DuplicationAnalyzer(),
        ExceptionsAnalyzer(),
        FileSizesAnalyzer(),
    ]
    result = run_scan(
        root=target if target.is_dir() else target.parent,
        analyzers=analyzers,
        project_id="",
    )

    output = export_result(result, fmt=args.export_format, top_n=args.export_top)

    if args.export_output:
        out: Path = args.export_output
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        print(f"Export written to {out}", file=sys.stderr)
    else:
        print(output)

    return 0


def _handle_dashboard(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit dashboard <path>``."""
    from code_audit.reports.dashboard import render_dashboard
    from code_audit.reports.trend_analysis import compute_trend, load_trend_data

    target: Path = args.dash_path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Run scan
    analyzers = [
        ComplexityAnalyzer(),
        DuplicationAnalyzer(),
        ExceptionsAnalyzer(),
        FileSizesAnalyzer(),
    ]
    result = run_scan(
        root=target if target.is_dir() else target.parent,
        analyzers=analyzers,
        project_id="",
    )

    # Optionally load trend data
    trend_direction = ""
    trend_delta = 0
    reg_dir = args.dash_registry_dir
    if reg_dir and reg_dir.exists():
        summaries = load_trend_data(reg_dir)
        trend = compute_trend(summaries)
        trend_direction = trend.direction
        trend_delta = trend.delta

    dashboard = render_dashboard(
        result,
        trend_direction=trend_direction,
        trend_delta=trend_delta,
        width=args.dash_width,
    )
    print(dashboard)
    return 0


def _handle_predict(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit predict <path>``."""
    from code_audit.core.discover import discover_py_files
    from code_audit.ml.bug_predictor import BugPredictor

    target: Path = args.predict_path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    files = discover_py_files(target)
    predictor = BugPredictor()
    predictions = predictor.predict(target, files)

    # Limit to top N
    top_n = args.predict_top
    shown = predictions[:top_n]

    if getattr(args, "json_out", False):
        json.dump(
            [
                {
                    "path": str(p.path),
                    "probability": round(p.probability, 4),
                    "risk_factors": p.risk_factors,
                }
                for p in shown
            ],
            sys.stdout,
            indent=2,
        )
        print()
    else:
        if not shown:
            print("No files to predict on.", file=sys.stderr)
        else:
            print(
                f"\n  Top {len(shown)} files by bug probability:\n",
                file=sys.stderr,
            )
            for p in shown:
                pct = f"{p.probability * 100:.1f}%"
                factors = ", ".join(p.risk_factors) if p.risk_factors else "none"
                print(
                    f"    {pct:>6s}  {p.path}  ({factors})",
                    file=sys.stderr,
                )
            print("", file=sys.stderr)

    return 0


def _handle_cluster(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit cluster <path>``."""
    from code_audit.core.discover import discover_py_files
    from code_audit.ml.code_clustering import CodeClusterer

    target: Path = args.cluster_path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Parse k
    k_arg = args.cluster_k
    if k_arg == "auto":
        n_clusters: int | str = "auto"
    else:
        try:
            n_clusters = int(k_arg)
        except ValueError:
            print(f"error: --k must be an integer or 'auto', got '{k_arg}'", file=sys.stderr)
            return 2

    files = discover_py_files(target)
    clusterer = CodeClusterer(n_clusters=n_clusters)
    result = clusterer.cluster(target, files)

    if getattr(args, "json_out", False):
        json.dump(
            {
                "clusters": [
                    {
                        "cluster_id": c.cluster_id,
                        "label": c.label,
                        "members": [str(m) for m in c.members],
                        "centroid": [round(v, 4) for v in c.centroid],
                    }
                    for c in result.clusters
                ],
                "outliers": [str(o) for o in result.outliers],
                "inertia": round(result.inertia, 4),
            },
            sys.stdout,
            indent=2,
        )
        print()
    else:
        print(result.summary())

    return 0


def _handle_debt(args: argparse.Namespace) -> int:
    """Dispatch ``code-audit debt scan|plan|snapshot|compare``."""
    from code_audit.core.discover import discover_py_files
    from code_audit.strangler.debt_detector import DebtDetector

    if args.debt_command in {"scan", "plan", "snapshot", "compare"}:
        target: Path = args.debt_path.resolve()
        if not target.exists():
            print(f"error: path does not exist: {target}", file=sys.stderr)
            return 2
    else:
        print(
            "error: use 'debt scan', 'debt plan', 'debt snapshot', "
            "or 'debt compare'.",
            file=sys.stderr,
        )
        return 2

    detector = DebtDetector()
    files = discover_py_files(target)

    if args.debt_command == "scan":
        findings = detector.run(target, files)
        if getattr(args, "json_out", False):
            json.dump(
                [f.to_dict() for f in findings],
                sys.stdout,
                indent=2,
                default=str,
            )
            print()
        else:
            if not findings:
                print("No structural debt detected.", file=sys.stderr)
            else:
                print(
                    f"\n  {len(findings)} debt item(s) detected:\n",
                    file=sys.stderr,
                )
                for f in findings:
                    sev = f.severity.value.upper()
                    loc = f"{f.location.path}:{f.location.line_start}"
                    print(f"    [{sev}]  {loc}  {f.message}", file=sys.stderr)
                print("", file=sys.stderr)
        return 1 if findings else 0

    if args.debt_command == "plan":
        from code_audit.strangler.plan_generator import generate_plan

        debt_items = detector.detect(target, files)
        plan = generate_plan(
            debt_items,
            project_id=getattr(args, "debt_project_id", "") or "",
        )
        if args.output:
            out: Path = args.output
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(plan, encoding="utf-8")
            print(f"Plan written to {out}", file=sys.stderr)
        else:
            print(plan)
        return 0

    if args.debt_command == "snapshot":
        from code_audit.strangler.debt_registry import DebtRegistry

        debt_items = detector.detect(target, files)
        reg_dir = args.registry_dir or (target / ".debt_snapshots")
        registry = DebtRegistry(reg_dir)
        path = registry.save_snapshot(args.name, debt_items)
        print(
            f"Snapshot '{args.name}' saved ({len(debt_items)} items) → {path}",
            file=sys.stderr,
        )
        return 0

    if args.debt_command == "compare":
        from code_audit.strangler.debt_registry import DebtRegistry

        debt_items = detector.detect(target, files)
        reg_dir = args.registry_dir or (target / ".debt_snapshots")
        registry = DebtRegistry(reg_dir)
        try:
            baseline_items = registry.load_snapshot(args.baseline)
        except FileNotFoundError:
            print(
                f"error: baseline snapshot '{args.baseline}' not found in {reg_dir}",
                file=sys.stderr,
            )
            return 2

        diff = DebtRegistry.compare(baseline_items, debt_items)

        if getattr(args, "json_out", False):
            json.dump(
                {
                    "new": [d.to_dict() for d in diff.new_items],
                    "resolved": [d.to_dict() for d in diff.resolved_items],
                    "unchanged": len(diff.unchanged_items),
                },
                sys.stdout,
                indent=2,
                default=str,
            )
            print()
        else:
            print(f"\n  Debt comparison vs '{args.baseline}':", file=sys.stderr)
            print(f"    {diff.summary()}", file=sys.stderr)
            if diff.new_items:
                print("\n  New debt:", file=sys.stderr)
                for d in diff.new_items:
                    print(
                        f"    + [{d.debt_type.value}] {d.path}:{d.line_start} "
                        f"{d.symbol}",
                        file=sys.stderr,
                    )
            if diff.resolved_items:
                print("\n  Resolved debt:", file=sys.stderr)
                for d in diff.resolved_items:
                    print(
                        f"    - [{d.debt_type.value}] {d.path}:{d.line_start} "
                        f"{d.symbol}",
                        file=sys.stderr,
                    )
            print("", file=sys.stderr)

        # Ratchet: exit 1 if new debt introduced
        return 1 if diff.has_new_debt else 0

    return 2


def main(argv: list[str] | None = None) -> int:
    """Entry-point — returns an exit code (0 = green, 1 = yellow, 2 = red)."""
    args = _build_parser().parse_args(argv)

    # ── validate subcommand ─────────────────────────────────────────
    if args.command == "validate":
        try:
            validate_file(args.instance, args.schema_name)
        except Exception as e:
            print(f"FAIL: {e}", file=sys.stderr)
            return 1
        print("OK")
        return 0

    # ── fence subcommand ─────────────────────────────────────────────
    if args.command == "fence":
        return _handle_fence(args)

    # ── governance subcommand ──────────────────────────────────────
    if args.command == "governance":
        return _handle_governance(args)

    # ── report subcommand ───────────────────────────────────────────
    if args.command == "report":
        return _handle_report(args)

    # ── debt subcommand (Strangler Fig) ─────────────────────────────
    if args.command == "debt":
        return _handle_debt(args)

    # ── inventory subcommand ────────────────────────────────────────
    if args.command == "inventory":
        return _handle_inventory(args)

    # ── sdk-boundary subcommand ─────────────────────────────────────
    if args.command == "sdk-boundary":
        return _handle_sdk_boundary(args)

    # ── truth-map subcommand ────────────────────────────────────────
    if args.command == "truth-map":
        return _handle_truth_map(args)

    # ── trend subcommand (Phase 7) ──────────────────────────────────
    if args.command == "trend":
        return _handle_trend(args)

    # ── export subcommand (Phase 7) ─────────────────────────────────
    if args.command == "export":
        return _handle_export(args)

    # ── dashboard subcommand (Phase 7) ──────────────────────────────
    if args.command == "dashboard":
        return _handle_dashboard(args)

    # ── predict subcommand (Phase 7 ML) ─────────────────────────────
    if args.command == "predict":
        return _handle_predict(args)

    # ── cluster subcommand (Phase 7 ML) ─────────────────────────────
    if args.command == "cluster":
        return _handle_cluster(args)

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

        # Optionally emit signals_latest.json alongside
        if args.emit_signals:

            emit_rel = Path(args.emit_signals)
            if emit_rel.is_absolute():
                print("error: --emit-signals must be a relative path under --out", file=sys.stderr)
                return 2
            # Prevent path traversal (keep companion artifacts co-located)
            resolved = (out_path.parent / emit_rel).resolve()
            out_root = out_path.parent.resolve()
            if out_root not in resolved.parents and resolved != out_root:
                print("error: --emit-signals must stay within the --out directory", file=sys.stderr)
                return 2
            from datetime import datetime, timezone

            signals_latest = {
                "schema_version": "signals_latest_v1",
                "run_id": result_dict["run"]["run_id"],
                "computed_at": result_dict["run"]["created_at"],
                "signal_logic_version": result_dict["run"]["signal_logic_version"],
                "copy_version": result_dict["run"]["copy_version"],
                "signals": result_dict.get("signals_snapshot", []),
            }
            signals_path = out_path.parent / args.emit_signals
            signals_path.write_text(
                json.dumps(signals_latest, indent=2, default=str) + "\n",
                encoding="utf-8",
            )

        _print_human(result_dict)
        tier = result_dict.get("summary", {}).get("vibe_tier", "red")
        return {"green": 0, "yellow": 1, "red": 2}.get(str(tier), 2)

    # ── default positional-path mode (class-based pipeline) ─────────
    if args.path is None:
        print("error: please provide a path or use a subcommand.", file=sys.stderr)
        return 2

    target: Path = args.path.resolve()
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    # Default analyzers
    analyzers = [
        ComplexityAnalyzer(),
        DuplicationAnalyzer(),
        ExceptionsAnalyzer(),
        FileSizesAnalyzer(),
    ]

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
    return _exit_code_from_score(score)


if __name__ == "__main__":
    raise SystemExit(main())
