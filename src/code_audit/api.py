"""
code_audit.api
==============

Programmatic entrypoints for using code_audit as a backend engine.

Goals:
  - No argparse / CLI dependencies
  - Deterministic mode support (ci_mode=True)
  - Stable, JSON-friendly outputs that match existing contracts

Non-goals:
  - Owning persistence (DB/storage) — callers handle storage
  - Owning presentation (UI strings) — callers render results

Usage::

    from code_audit.api import scan_project, snapshot_debt, compare_debt

    result, result_dict = scan_project(".", ci_mode=True)
    snap = snapshot_debt(".", ci_mode=True)
    diff = compare_debt(baseline=snap, root=".", ci_mode=True)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from code_audit.analyzers.complexity import ComplexityAnalyzer
from code_audit.analyzers.dead_code import DeadCodeAnalyzer
from code_audit.analyzers.duplication import DuplicationAnalyzer
from code_audit.analyzers.exceptions import ExceptionsAnalyzer
from code_audit.analyzers.file_sizes import FileSizesAnalyzer
from code_audit.analyzers.global_state import GlobalStateAnalyzer
from code_audit.analyzers.routers import RoutersAnalyzer
from code_audit.analyzers.security import SecurityAnalyzer
from code_audit.analyzers.deployment import DeploymentAnalyzer
from code_audit.analyzers.sql_ecosystem import SQLEcosystemAnalyzer
from code_audit.core.discover import discover_py_files
from code_audit.core.runner import run_scan
from code_audit.model.run_result import RunResult
from code_audit.strangler.debt_detector import DebtDetector
from code_audit.strangler.debt_registry import DebtRegistry

# Fixed timestamp for deterministic mode (matches CLI contract).
_DETERMINISTIC_TIMESTAMP = "2000-01-01T00:00:00+00:00"

# Default analyzer set — matches what the CLI's `scan` command uses.
_DEFAULT_ANALYZERS = (
    ComplexityAnalyzer,
    DeadCodeAnalyzer,
    DeploymentAnalyzer,
    DuplicationAnalyzer,
    ExceptionsAnalyzer,
    FileSizesAnalyzer,
    GlobalStateAnalyzer,
    RoutersAnalyzer,
    SecurityAnalyzer,
    SQLEcosystemAnalyzer,
)


def _to_path(p: str | Path) -> Path:
    return p if isinstance(p, Path) else Path(p)


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── scan_project ────────────────────────────────────────────────────


def scan_project(
    root: str | Path,
    *,
    project_id: str = "",
    config: Optional[dict[str, Any]] = None,
    ci_mode: bool = False,
    analyzers: Optional[list[Any]] = None,
) -> tuple[RunResult, dict[str, Any]]:
    """Run the standard scan pipeline programmatically.

    Parameters
    ----------
    root:
        Directory to scan.
    project_id:
        Optional identifier for the project.
    config:
        Optional config dict (include/exclude globs).
    ci_mode:
        If True, output is byte-deterministic (fixed timestamps, sorted).
    analyzers:
        Override the default analyzer set. Each must conform to the
        ``Analyzer`` protocol (``id``, ``version``, ``run()``).

    Returns
    -------
    ``(RunResult, run_result_dict)``
        The dataclass and the schema-aligned JSON dict.

    Raises
    ------
    FileNotFoundError
        If *root* does not exist.
    """
    root_p = _to_path(root).resolve()
    if not root_p.exists():
        raise FileNotFoundError(f"scan_project: root does not exist: {root_p}")

    analyzer_instances = (
        analyzers if analyzers is not None else [cls() for cls in _DEFAULT_ANALYZERS]
    )

    kwargs: dict[str, Any] = {
        "project_id": project_id,
        "config": config or {},
        "ci_mode": ci_mode,
    }
    if ci_mode:
        kwargs["_created_at"] = _DETERMINISTIC_TIMESTAMP
        # Deterministic run_id: content-hash of Python files in root.
        h = hashlib.sha256()
        for p in sorted(root_p.rglob("*.py")):
            try:
                rel = p.resolve().relative_to(root_p).as_posix()
                h.update(rel.encode("utf-8"))
                h.update(str(p.stat().st_size).encode("utf-8"))
            except (OSError, ValueError):
                h.update(b"0")
        kwargs["_run_id"] = "ci-" + h.hexdigest()[:12]

    rr = run_scan(root_p, analyzer_instances, **kwargs)
    rr_dict = rr.to_dict()
    return rr, rr_dict


# ── snapshot_debt ───────────────────────────────────────────────────


def snapshot_debt(
    root: str | Path,
    *,
    ci_mode: bool = False,
) -> dict[str, Any]:
    """Produce a ``debt_snapshot_v1`` artifact as an in-memory dict.

    This is the canonical ratchet baseline substrate.
    Callers can serialize it to a file (e.g. ``baselines/main.json``)
    using the repo's stable JSON normalization layer.

    Parameters
    ----------
    root:
        Directory to scan for structural debt.
    ci_mode:
        If True, timestamps and ordering are deterministic.

    Returns
    -------
    A dict conforming to ``debt_snapshot_v1``.

    Raises
    ------
    FileNotFoundError
        If *root* does not exist.
    """
    root_p = _to_path(root).resolve()
    if not root_p.exists():
        raise FileNotFoundError(f"snapshot_debt: root does not exist: {root_p}")

    detector = DebtDetector()
    files = discover_py_files(root_p)
    items = detector.detect(root_p, files)

    # Deterministic ordering: (path, line_start, symbol, fingerprint)
    items = sorted(
        items,
        key=lambda d: (d.path, d.line_start, d.symbol, d.fingerprint),
    )

    created_at = _DETERMINISTIC_TIMESTAMP if ci_mode else _now_iso_utc()
    return {
        "schema_version": "debt_snapshot_v1",
        "created_at": created_at,
        "debt_count": len(items),
        "items": [i.to_dict() for i in items],
    }


# ── compare_debt ───────────────────────────────────────────────────


def compare_debt(
    *,
    baseline: dict[str, Any] | str | Path,
    current: dict[str, Any] | str | Path | None = None,
    root: str | Path | None = None,
    ci_mode: bool = False,
) -> dict[str, Any]:
    """Compare two debt snapshots and return a JSON-friendly diff.

    Parameters
    ----------
    baseline:
        A ``debt_snapshot_v1`` dict **or** path to a JSON file.
    current:
        A ``debt_snapshot_v1`` dict **or** path to a JSON file.
        If ``None``, a live snapshot is generated from *root*.
    root:
        Required when *current* is ``None`` (live snapshot).
    ci_mode:
        Forwarded to ``snapshot_debt`` when generating a live snapshot.

    Returns
    -------
    A dict with keys: ``schema_version``, ``baseline_ref``, ``current_ref``,
    ``new``, ``resolved``, ``unchanged``, ``has_new_debt``.

    Raises
    ------
    ValueError
        If schema versions don't match ``debt_snapshot_v1``.
    FileNotFoundError
        If a path-based input does not exist.
    """
    baseline_data = _load_snapshot_input(baseline, source_label="baseline")
    _require_debt_snapshot_v1(baseline_data, source="baseline")

    if current is None:
        if root is None:
            raise ValueError("compare_debt: root is required when current is None")
        current_data = snapshot_debt(root, ci_mode=ci_mode)
        current_ref = f"live:{_to_path(root).resolve()}"
    else:
        current_data = _load_snapshot_input(current, source_label="current")
        _require_debt_snapshot_v1(current_data, source="current")
        current_ref = _input_ref(current)

    baseline_ref = _input_ref(baseline)

    baseline_items = DebtRegistry._items_from_snapshot_dict(baseline_data)
    current_items = DebtRegistry._items_from_snapshot_dict(current_data)

    diff = DebtRegistry.compare(baseline_items, current_items)

    # Deterministic ordering in diff lists.
    new_sorted = sorted(
        diff.new_items,
        key=lambda d: (d.path, d.line_start, d.symbol, d.fingerprint),
    )
    resolved_sorted = sorted(
        diff.resolved_items,
        key=lambda d: (d.path, d.line_start, d.symbol, d.fingerprint),
    )

    return {
        "schema_version": "debt_compare_v1",
        "baseline_ref": baseline_ref,
        "current_ref": current_ref,
        "new": [d.to_dict() for d in new_sorted],
        "resolved": [d.to_dict() for d in resolved_sorted],
        "unchanged": len(diff.unchanged_items),
        "has_new_debt": bool(diff.has_new_debt),
    }


# ── validate_instance ──────────────────────────────────────────────


def validate_instance(
    instance: dict[str, Any],
    schema_name: str,
) -> None:
    """Validate a Python dict against a named bundled schema.

    This is a backend-friendly alternative to the CLI ``validate`` command.

    Parameters
    ----------
    instance:
        The dict to validate.
    schema_name:
        The schema filename (e.g. ``"run_result.schema.json"``).

    Raises
    ------
    jsonschema.ValidationError
        If validation fails.
    RuntimeError
        If ``jsonschema`` is not installed.
    """
    try:
        import jsonschema
    except ImportError as e:
        raise RuntimeError(
            "validate_instance requires jsonschema (install code-audit[dev])"
        ) from e

    from code_audit.contracts.load import load_schema

    schema = load_schema(schema_name)
    jsonschema.validate(instance=instance, schema=schema)


# ── internal helpers ───────────────────────────────────────────────


def _input_ref(x: Any) -> str:
    if isinstance(x, (str, Path)):
        return str(_to_path(x))
    return "in-memory"


def _load_snapshot_input(
    x: dict[str, Any] | str | Path,
    *,
    source_label: str,
) -> dict[str, Any]:
    if isinstance(x, dict):
        return x
    p = _to_path(x)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"{source_label}: snapshot file not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _require_debt_snapshot_v1(data: dict[str, Any], *, source: str) -> None:
    sv = data.get("schema_version")
    if sv != "debt_snapshot_v1":
        raise ValueError(
            f"{source}: expected schema_version='debt_snapshot_v1', got {sv!r}"
        )


# ── governance_audit ─────────────────────────────────────────────────


def governance_audit(
    root: str | Path,
    *,
    gates: list[str] | None = None,
) -> dict[str, Any]:
    """Run governance checks on a codebase.

    Parameters
    ----------
    root:
        Directory to scan.
    gates:
        List of gate names to run. If None, runs all gates.
        Available: "deprecation", "import_ban", "legacy_usage", "sdk_boundary"

    Returns
    -------
    Dict with gate results: {"gate_name": {"passed": bool, "violations": [...]}}
    """
    from code_audit.governance.deprecation import DeprecationAnalyzer
    from code_audit.governance.import_ban import ImportBanAnalyzer
    from code_audit.governance.legacy_usage import LegacyUsageAnalyzer
    from code_audit.governance.sdk_boundary import SdkBoundaryAnalyzer

    root_p = _to_path(root).resolve()
    if not root_p.exists():
        raise FileNotFoundError(f"governance_audit: root does not exist: {root_p}")

    all_gates = {
        "deprecation": DeprecationAnalyzer,
        "import_ban": ImportBanAnalyzer,
        "legacy_usage": LegacyUsageAnalyzer,
        "sdk_boundary": SdkBoundaryAnalyzer,
    }

    gates_to_run = gates if gates else list(all_gates.keys())
    results: dict[str, Any] = {}

    files = discover_py_files(root_p)

    for gate_name in gates_to_run:
        if gate_name not in all_gates:
            results[gate_name] = {"passed": False, "error": f"Unknown gate: {gate_name}"}
            continue

        try:
            checker = all_gates[gate_name]()
            violations = checker.run(root_p, files)
            results[gate_name] = {
                "passed": len(violations) == 0,
                "violation_count": len(violations),
                "violations": [v.to_dict() if hasattr(v, "to_dict") else str(v) for v in violations],
            }
        except Exception as e:
            results[gate_name] = {"passed": False, "error": str(e)}

    return results


# ── detect_debt_patterns ─────────────────────────────────────────────


def detect_debt_patterns(
    root: str | Path,
) -> dict[str, Any]:
    """Detect structural technical debt patterns.

    Parameters
    ----------
    root:
        Directory to scan.

    Returns
    -------
    Dict with debt analysis: {"debt_count": int, "items": [...], "by_type": {...}}
    """
    root_p = _to_path(root).resolve()
    if not root_p.exists():
        raise FileNotFoundError(f"detect_debt_patterns: root does not exist: {root_p}")

    detector = DebtDetector()
    files = discover_py_files(root_p)
    items = detector.detect(root_p, files)

    # Group by type
    by_type: dict[str, int] = {}
    for item in items:
        debt_type = item.debt_type.value if hasattr(item.debt_type, "value") else str(item.debt_type)
        by_type[debt_type] = by_type.get(debt_type, 0) + 1

    return {
        "debt_count": len(items),
        "items": [i.to_dict() for i in items],
        "by_type": by_type,
    }
