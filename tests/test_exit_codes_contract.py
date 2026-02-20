"""Exit code contract tests — enforce stable CLI exit semantics.

Code  Meaning
----  -------
  0   Success — no violations detected
  1   Violation — policy / contract failure
  2   Error — usage error, missing file, runtime failure
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    env["PYTHONPATH"] = str(REPO_ROOT / "src") + (
        ":" + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else ""
    )
    env["CI"] = "true"
    return subprocess.run(
        [sys.executable, "-m", "code_audit", *args],
        capture_output=True,
        text=True,
        env=env,
    )


# ── Debt snapshot / compare exit codes ──────────────────────────────

class TestDebtExitCodes:
    """Debt compare: 0 = clean, 1 = new debt, 2 = runtime error."""

    def test_debt_compare_clean_vs_baseline_returns_0(self, tmp_path: Path) -> None:
        """Same snapshot as both baseline and current → exit 0."""
        root = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
        snap = tmp_path / "snap.json"

        r = _run("debt", "snapshot", str(root), "--out", str(snap), "--ci")
        assert r.returncode == 0, r.stderr

        # Compare snapshot against itself → no new debt
        rc = _run(
            "debt", "compare", str(root),
            "--baseline", str(snap),
            "--current", str(snap),
            "--ci",
        )
        assert rc.returncode == 0, rc.stderr

    def test_debt_compare_with_new_debt_returns_1(self, tmp_path: Path) -> None:
        """Clean baseline vs debt-laden current → exit 1."""
        clean = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"
        debt = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"

        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"

        rb = _run("debt", "snapshot", str(clean), "--out", str(baseline), "--ci")
        assert rb.returncode == 0, rb.stderr

        rc = _run("debt", "snapshot", str(debt), "--out", str(current), "--ci")
        assert rc.returncode == 0, rc.stderr

        rcmp = _run(
            "debt", "compare", str(debt),
            "--baseline", str(baseline),
            "--current", str(current),
            "--ci", "--json",
        )
        assert rcmp.returncode == 1, rcmp.stderr

    def test_debt_compare_missing_baseline_returns_2(self, tmp_path: Path) -> None:
        """Nonexistent baseline file → exit 2."""
        debt = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
        current = tmp_path / "current.json"

        rc = _run("debt", "snapshot", str(debt), "--out", str(current), "--ci")
        assert rc.returncode == 0, rc.stderr

        rcmp = _run(
            "debt", "compare", str(debt),
            "--baseline", str(tmp_path / "nonexistent.json"),
            "--current", str(current),
            "--ci",
        )
        assert rcmp.returncode == 2, rcmp.stdout + "\n" + rcmp.stderr


# ── Validate exit codes ─────────────────────────────────────────────

class TestValidateExitCodes:
    """validate: 0 = valid, 1 = invalid instance."""

    def test_validate_good_schema_returns_0(self) -> None:
        schema_example = REPO_ROOT / "schemas" / "debt_snapshot.example.json"
        r = _run("validate", str(schema_example), "debt_snapshot.schema.json")
        assert r.returncode == 0, r.stderr

    def test_validate_bad_instance_returns_1(self, tmp_path: Path) -> None:
        # Content violation (valid schema_version but missing required fields)
        bad = tmp_path / "bad.json"
        bad.write_text(
            '{"schema_version": "debt_snapshot_v1", "debt_count": 0}',
            encoding="utf-8",
        )
        r = _run("validate", str(bad), "debt_snapshot.schema.json")
        assert r.returncode == 1, r.stdout

    def test_validate_wrong_schema_version_returns_1(self, tmp_path: Path) -> None:
        # Wrong schema_version violates the JSON schema's "const" constraint →
        # jsonschema.ValidationError → exit 1 (violation).
        bad = tmp_path / "bad.json"
        bad.write_text('{"schema_version": "wrong"}', encoding="utf-8")
        r = _run("validate", str(bad), "debt_snapshot.schema.json")
        assert r.returncode == 1, r.stdout


# ── Debt scan exit codes ────────────────────────────────────────────

class TestDebtScanExitCodes:
    """debt scan: 0 = no debt, 1 = debt present."""

    def test_scan_no_debt_returns_0(self) -> None:
        clean = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"
        r = _run("debt", "scan", str(clean))
        assert r.returncode == 0, r.stderr

    def test_scan_debt_present_returns_1(self) -> None:
        debt = REPO_ROOT / "tests" / "fixtures" / "sample_repo_debt"
        r = _run("debt", "scan", str(debt))
        assert r.returncode == 1, r.stderr


# ── CI required-keys guard ──────────────────────────────────────────

class TestCiRequiredKeysGuard:
    """_ci_required_keys_check rejects malformed API output with exit 2."""

    @pytest.fixture(autouse=True)
    def _import_guard(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "code_audit.__main__",
            REPO_ROOT / "src" / "code_audit" / "__main__.py",
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self._check = mod._ci_required_keys_check
        self._ERROR = mod.ExitCode.ERROR

    def _good_result(self) -> dict:
        return {
            "run": {"run_id": "abc", "created_at": "2026-01-01T00:00:00+00:00"},
            "summary": {
                "confidence_score": 80,
                "vibe_tier": "green",
                "counts": {"findings_total": 0},
            },
        }

    def test_good_result_returns_none(self):
        assert self._check(self._good_result()) is None

    def test_missing_run_returns_error(self):
        d = self._good_result()
        del d["run"]
        assert self._check(d) == self._ERROR

    def test_missing_summary_returns_error(self):
        d = self._good_result()
        del d["summary"]
        assert self._check(d) == self._ERROR

    def test_missing_run_id_returns_error(self):
        d = self._good_result()
        del d["run"]["run_id"]
        assert self._check(d) == self._ERROR

    def test_missing_vibe_tier_returns_error(self, capsys):
        d = self._good_result()
        del d["summary"]["vibe_tier"]
        assert self._check(d) == self._ERROR
        err = capsys.readouterr().err
        assert "summary.vibe_tier" in err

    def test_missing_confidence_score_returns_error(self):
        d = self._good_result()
        del d["summary"]["confidence_score"]
        assert self._check(d) == self._ERROR

    def test_missing_counts_returns_error(self):
        d = self._good_result()
        del d["summary"]["counts"]
        assert self._check(d) == self._ERROR

    def test_missing_findings_total_returns_error(self):
        d = self._good_result()
        del d["summary"]["counts"]["findings_total"]
        assert self._check(d) == self._ERROR

    def test_counts_not_dict_returns_error(self):
        d = self._good_result()
        d["summary"]["counts"] = "not a dict"
        assert self._check(d) == self._ERROR
