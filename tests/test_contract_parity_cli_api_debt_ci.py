"""Contract parity: CLI debt snapshot/compare == API output under --ci.

Level 3 parity test.  Any hidden compute or serialization divergence
in the CLI will break byte-identity immediately.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from code_audit.api import compare_debt, snapshot_debt
from code_audit.utils.json_norm import stable_json_dumps

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SRC = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["CODE_AUDIT_DETERMINISTIC"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return env


def _norm(b: bytes) -> bytes:
    """Normalize CRLF → LF for cross-platform byte comparison."""
    return b.replace(b"\r\n", b"\n")


def test_contract_parity_debt_snapshot_ci(tmp_path: Path) -> None:
    """CLI debt snapshot --ci --out file == API snapshot_debt(ci_mode=True)."""
    workdir = tmp_path / "repo"
    shutil.copytree(FIXTURE_SRC, workdir)

    # API (canonical)
    api_snap = snapshot_debt(workdir, ci_mode=True)
    api_bytes = stable_json_dumps(api_snap, indent=2, ci_mode=True).encode("utf-8")

    # CLI snapshot
    snap_file = tmp_path / "baseline.json"
    p = subprocess.run(
        [
            sys.executable, "-m", "code_audit",
            "debt", "snapshot", str(workdir),
            "--ci", "--out", str(snap_file),
        ],
        env=_cli_env(),
        capture_output=True,
    )
    assert p.returncode == 0, (p.stdout, p.stderr)
    assert _norm(api_bytes) == _norm(snap_file.read_bytes())


def test_contract_parity_debt_compare_ci(tmp_path: Path) -> None:
    """CLI debt compare --ci --json stdout == API compare result (subset keys)."""
    workdir = tmp_path / "repo"
    shutil.copytree(FIXTURE_SRC, workdir)

    # Baseline via API
    api_baseline = snapshot_debt(workdir, ci_mode=True)
    baseline_file = tmp_path / "baseline.json"
    baseline_file.write_text(
        stable_json_dumps(api_baseline, indent=2, ci_mode=True),
        encoding="utf-8",
    )

    # Introduce new debt deterministically
    target = workdir / "src" / "app.py"
    if not target.exists():
        target = workdir / "app.py"
    original = target.read_text(encoding="utf-8")
    injected = (
        original
        + "\n\n"
        + "def _intentional_god_function_for_ratchet():\n"
        + "    total = 0\n"
        + "".join(f"    total += {i}\n" for i in range(80))
        + "    return total\n"
    )
    target.write_text(injected, encoding="utf-8")

    # Current snapshot via API
    api_current = snapshot_debt(workdir, ci_mode=True)
    current_file = tmp_path / "current.json"
    current_file.write_text(
        stable_json_dumps(api_current, indent=2, ci_mode=True),
        encoding="utf-8",
    )

    # API compare (canonical)
    api_cmp = compare_debt(
        baseline=api_baseline, current=api_current, ci_mode=True,
    )
    # CLI emits {new, resolved, unchanged} without schema_version wrapper
    api_cmp_subset = {
        "new": api_cmp["new"],
        "resolved": api_cmp["resolved"],
        "unchanged": api_cmp["unchanged"],
    }
    api_cmp_bytes = stable_json_dumps(
        api_cmp_subset, indent=2, ci_mode=True,
    ).encode("utf-8")

    # CLI compare
    p = subprocess.run(
        [
            sys.executable, "-m", "code_audit",
            "debt", "compare", str(workdir),
            "--baseline", str(baseline_file),
            "--current", str(current_file),
            "--ci", "--json",
        ],
        env=_cli_env(),
        capture_output=True,
    )
    assert p.returncode == 1, (p.stdout, p.stderr)  # new debt → violation
    assert _norm(api_cmp_bytes) == _norm(p.stdout)
