"""Tests for code_audit.api — programmatic engine entrypoints.

Validates the public API surface that backends/services use
without CLI coupling.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from code_audit.api import compare_debt, scan_project, snapshot_debt, validate_instance


FIXTURE_REPO = Path(__file__).resolve().parent / "fixtures" / "sample_repo_debt"


# ── snapshot_debt ───────────────────────────────────────────────────


class TestSnapshotDebt:
    """snapshot_debt produces a valid debt_snapshot_v1 dict."""

    def test_returns_v1_shape(self) -> None:
        snap = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        assert snap["schema_version"] == "debt_snapshot_v1"
        assert "created_at" in snap
        assert isinstance(snap["debt_count"], int)
        assert isinstance(snap["items"], list)

    def test_ci_mode_fixes_timestamp(self) -> None:
        snap = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        assert snap["created_at"] == "2000-01-01T00:00:00+00:00"

    def test_deterministic_across_runs(self) -> None:
        a = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        b = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        assert a == b, "Two ci_mode snapshots must be identical"

    def test_detects_god_function(self) -> None:
        snap = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        assert snap["debt_count"] >= 1
        types = {item["debt_type"] for item in snap["items"]}
        assert "god_function" in types

    def test_nonexistent_root_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="does not exist"):
            snapshot_debt("/nonexistent/path/xyz")

    def test_validates_against_schema(self) -> None:
        snap = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        validate_instance(snap, "debt_snapshot.schema.json")


# ── compare_debt ────────────────────────────────────────────────────


class TestCompareDebt:
    """compare_debt produces a valid diff dict."""

    def test_baseline_equals_current_no_new_debt(self) -> None:
        baseline = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        current = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        diff = compare_debt(baseline=baseline, current=current, ci_mode=True)
        assert diff["schema_version"] == "debt_compare_v1"
        assert diff["has_new_debt"] is False
        assert diff["new"] == []

    def test_live_comparison_from_root(self) -> None:
        baseline = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        diff = compare_debt(baseline=baseline, root=FIXTURE_REPO, ci_mode=True)
        assert diff["has_new_debt"] is False

    def test_missing_root_when_current_is_none(self) -> None:
        baseline = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        with pytest.raises(ValueError, match="root is required"):
            compare_debt(baseline=baseline)

    def test_schema_version_enforcement(self) -> None:
        bad = {"schema_version": "wrong_v1", "items": []}
        with pytest.raises(ValueError, match="debt_snapshot_v1"):
            compare_debt(baseline=bad, current=bad)

    def test_file_based_baseline(self, tmp_path: Path) -> None:
        import json

        snap = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        f = tmp_path / "baseline.json"
        f.write_text(json.dumps(snap), encoding="utf-8")
        diff = compare_debt(baseline=f, current=snap, ci_mode=True)
        assert diff["has_new_debt"] is False


# ── scan_project ────────────────────────────────────────────────────


class TestScanProject:
    """scan_project returns a RunResult + dict pair."""

    def test_returns_tuple(self) -> None:
        rr, rr_dict = scan_project(FIXTURE_REPO, ci_mode=True)
        assert rr_dict["schema_version"] == "run_result_v1"
        assert "summary" in rr_dict
        assert "findings_raw" in rr_dict

    def test_ci_mode_deterministic(self) -> None:
        _, a = scan_project(FIXTURE_REPO, ci_mode=True)
        _, b = scan_project(FIXTURE_REPO, ci_mode=True)
        # created_at should be fixed-timestamp
        assert a["run"]["created_at"] == "2000-01-01T00:00:00+00:00"
        assert a["run"]["created_at"] == b["run"]["created_at"]

    def test_nonexistent_root_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="does not exist"):
            scan_project("/nonexistent/path/xyz")


# ── validate_instance ──────────────────────────────────────────────


class TestValidateInstance:
    """validate_instance validates dicts against bundled schemas."""

    def test_valid_snapshot_passes(self) -> None:
        snap = snapshot_debt(FIXTURE_REPO, ci_mode=True)
        validate_instance(snap, "debt_snapshot.schema.json")  # should not raise

    def test_invalid_snapshot_fails(self) -> None:
        import jsonschema

        bad = {"schema_version": "debt_snapshot_v1"}  # missing required fields
        with pytest.raises(jsonschema.ValidationError):
            validate_instance(bad, "debt_snapshot.schema.json")


# ── top-level import ────────────────────────────────────────────────


class TestTopLevelImport:
    """API is importable from the package root."""

    def test_import_from_code_audit(self) -> None:
        from code_audit import compare_debt, scan_project, snapshot_debt, validate_instance

        assert callable(scan_project)
        assert callable(snapshot_debt)
        assert callable(compare_debt)
        assert callable(validate_instance)
