"""Parity test: API snapshot_debt/compare_debt equals CLI debt output under --ci.

Validates that CLI ``debt snapshot --ci`` and ``debt compare --ci`` produce
byte-identical JSON to the programmatic API.  Proves the CLI routes through
a single canonical compute path.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from code_audit.api import compare_debt, snapshot_debt
from code_audit.utils.json_norm import stable_json_dumps

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DEBT = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["CODE_AUDIT_DETERMINISTIC"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    env["CI"] = "true"
    return env


# ── debt snapshot parity ────────────────────────────────────────────


class TestDebtSnapshotParity:
    """CLI ``debt snapshot --ci --out`` and API ``snapshot_debt(ci_mode=True)``
    produce identical JSON artifacts."""

    def test_snapshot_json_matches_api(self, tmp_path: Path) -> None:
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE_DEBT, work)

        # CI mode requires relative paths inside artifacts/
        (tmp_path / "artifacts").mkdir(exist_ok=True)
        cmd = [
            sys.executable, "-m", "code_audit",
            "debt", "snapshot", str(work),
            "--ci",
            "--out", "artifacts/snapshot.json",
        ]
        r = subprocess.run(cmd, env=_cli_env(), cwd=tmp_path, text=True, capture_output=True)
        assert r.returncode == 0, (
            f"CLI debt snapshot failed with exit {r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )

        cli_bytes = (tmp_path / "artifacts" / "snapshot.json").read_text(encoding="utf-8")

        # API snapshot
        api_dict = snapshot_debt(work, ci_mode=True)
        api_bytes = stable_json_dumps(api_dict, indent=2, ci_mode=True)

        assert cli_bytes == api_bytes, (
            "CLI debt snapshot --ci output differs from API snapshot_debt(ci_mode=True).\n"
            "This means there are two different compute paths."
        )

    def test_snapshot_deterministic_across_runs(self, tmp_path: Path) -> None:
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE_DEBT, work)

        # CI mode requires relative paths inside artifacts/
        (tmp_path / "artifacts").mkdir(exist_ok=True)
        for name in ("snap_a.json", "snap_b.json"):
            r = subprocess.run(
                [
                    sys.executable, "-m", "code_audit",
                    "debt", "snapshot", str(work),
                    "--ci", "--out", f"artifacts/{name}",
                ],
                env=_cli_env(), cwd=tmp_path, text=True, capture_output=True,
            )
            assert r.returncode == 0

        assert (tmp_path / "artifacts" / "snap_a.json").read_bytes() == (tmp_path / "artifacts" / "snap_b.json").read_bytes()


# ── debt compare parity ─────────────────────────────────────────────


class TestDebtCompareParity:
    """CLI ``debt compare --ci --json`` and API ``compare_debt(ci_mode=True)``
    produce identical JSON output."""

    def test_compare_no_new_debt_matches_api(self, tmp_path: Path) -> None:
        """Baseline == current → no new debt, CLI and API agree."""
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE_DEBT, work)

        # Create baseline via API (shared truth)
        baseline = snapshot_debt(work, ci_mode=True)
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(
            stable_json_dumps(baseline, indent=2, ci_mode=True),
            encoding="utf-8",
        )

        # Create current via API too
        current = snapshot_debt(work, ci_mode=True)
        current_file = tmp_path / "current.json"
        current_file.write_text(
            stable_json_dumps(current, indent=2, ci_mode=True),
            encoding="utf-8",
        )

        # CLI compare
        cmd = [
            sys.executable, "-m", "code_audit",
            "debt", "compare", str(work),
            "--baseline", str(baseline_file),
            "--current", str(current_file),
            "--ci", "--json",
        ]
        r = subprocess.run(cmd, env=_cli_env(), cwd=tmp_path, text=True, capture_output=True)
        assert r.returncode == 0, (
            f"CLI debt compare failed with exit {r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )
        cli_dict = json.loads(r.stdout)

        # API compare
        api_result = compare_debt(
            baseline=baseline, current=current, ci_mode=True
        )
        # CLI emits { new, resolved, unchanged } without schema_version wrapper
        api_dict = {
            "new": api_result["new"],
            "resolved": api_result["resolved"],
            "unchanged": api_result["unchanged"],
        }

        assert cli_dict == api_dict, (
            "CLI debt compare --ci --json output differs from API compare_debt.\n"
            "This means there are two different compute paths."
        )

    def test_compare_with_new_debt_exits_1(self, tmp_path: Path) -> None:
        """When new debt is introduced, both CLI and API report it."""
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE_DEBT, work)

        # Baseline: current state
        baseline = snapshot_debt(work, ci_mode=True)
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(
            stable_json_dumps(baseline, indent=2, ci_mode=True),
            encoding="utf-8",
        )

        # Introduce new debt: add another god function
        new_file = work / "new_debt.py"
        new_file.write_text(
            "def another_god_function(x):\n"
            + "".join(f"    total = x + {i}\n" for i in range(80))
            + "    return total\n",
            encoding="utf-8",
        )

        # CLI compare (live scan of modified work dir)
        cmd = [
            sys.executable, "-m", "code_audit",
            "debt", "compare", str(work),
            "--baseline", str(baseline_file),
            "--ci", "--json",
        ]
        r = subprocess.run(cmd, env=_cli_env(), cwd=tmp_path, text=True, capture_output=True)
        assert r.returncode == 1, (
            f"Expected exit 1 (new debt), got {r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )
        cli_dict = json.loads(r.stdout)
        assert len(cli_dict["new"]) >= 1

        # API compare
        api_result = compare_debt(baseline=baseline, root=work, ci_mode=True)
        assert api_result["has_new_debt"] is True
        assert len(api_result["new"]) >= 1

        # The new items should match
        api_new_sorted = sorted(api_result["new"], key=lambda d: (d["path"], d["symbol"]))
        cli_new_sorted = sorted(cli_dict["new"], key=lambda d: (d["path"], d["symbol"]))
        assert api_new_sorted == cli_new_sorted

    def test_compare_exit_code_parity(self, tmp_path: Path) -> None:
        """Exit code 0 when no new debt, 1 when new debt — matches API's has_new_debt."""
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE_DEBT, work)

        baseline = snapshot_debt(work, ci_mode=True)
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(
            stable_json_dumps(baseline, indent=2, ci_mode=True),
            encoding="utf-8",
        )

        # No new debt → exit 0
        cmd = [
            sys.executable, "-m", "code_audit",
            "debt", "compare", str(work),
            "--baseline", str(baseline_file),
            "--ci", "--json",
        ]
        r = subprocess.run(cmd, env=_cli_env(), cwd=tmp_path, text=True, capture_output=True)
        api_result = compare_debt(baseline=baseline, root=work, ci_mode=True)

        assert r.returncode == 0
        assert api_result["has_new_debt"] is False
