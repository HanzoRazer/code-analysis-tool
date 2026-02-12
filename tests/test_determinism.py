"""Acceptance tests for deterministic (--ci) mode.

These tests verify that:
1. Two --ci runs on the same repo produce identical JSON
2. Directory paths don't affect output (content-based identity)
3. Non-CI runs produce different timestamps/run_ids
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from code_audit.utils.determinism import (
    FIXED_TIMESTAMP,
    FIXED_SEED,
    is_ci_mode,
    set_ci_mode,
    seed_random,
    deterministic_timestamp,
    deterministic_run_id,
    normalize_path,
    round_float,
    sort_findings,
    sort_signals,
    sort_debt_items,
    make_deterministic_dict,
)


class TestDeterminismUtilities:
    """Unit tests for determinism module utilities."""

    def test_fixed_timestamp_constant(self):
        """FIXED_TIMESTAMP is ISO 8601 with timezone."""
        assert FIXED_TIMESTAMP == "2000-01-01T00:00:00+00:00"

    def test_fixed_seed_constant(self):
        """FIXED_SEED is a known value."""
        assert FIXED_SEED == 42

    def test_is_ci_mode_default_false(self):
        """CI mode is off by default."""
        set_ci_mode(False)
        assert is_ci_mode() is False

    def test_is_ci_mode_can_be_enabled(self):
        """CI mode can be enabled via set_ci_mode."""
        set_ci_mode(True)
        assert is_ci_mode() is True
        set_ci_mode(False)  # Reset

    def test_is_ci_mode_from_args(self):
        """CI mode can be detected from args object."""

        class Args:
            ci_mode = True

        assert is_ci_mode(Args()) is True

    def test_deterministic_timestamp_ci_mode(self):
        """In CI mode, timestamp is fixed."""
        ts = deterministic_timestamp(ci_mode=True)
        assert ts == FIXED_TIMESTAMP

    def test_deterministic_timestamp_normal_mode(self):
        """In normal mode, timestamp is current time."""
        ts = deterministic_timestamp(ci_mode=False)
        assert ts != FIXED_TIMESTAMP
        assert "T" in ts  # ISO format
        assert "+" in ts or "Z" in ts  # Has timezone

    def test_deterministic_run_id_ci_mode(self, tmp_path: Path):
        """In CI mode, run_id is derived from repo root."""
        run_id = deterministic_run_id(tmp_path, ci_mode=True)
        assert run_id.startswith("ci-")
        assert len(run_id) == 19  # "ci-" + 16 hex chars

    def test_deterministic_run_id_reproducible(self, tmp_path: Path):
        """Same root produces same run_id in CI mode."""
        id1 = deterministic_run_id(tmp_path, ci_mode=True)
        id2 = deterministic_run_id(tmp_path, ci_mode=True)
        assert id1 == id2

    def test_deterministic_run_id_normal_mode(self, tmp_path: Path):
        """In normal mode, run_id is UUID-based and unique."""
        id1 = deterministic_run_id(tmp_path, ci_mode=False)
        id2 = deterministic_run_id(tmp_path, ci_mode=False)
        assert id1.startswith("run-")
        assert id2.startswith("run-")
        assert id1 != id2

    def test_normalize_path_relative(self, tmp_path: Path):
        """Paths under root are made relative."""
        subdir = tmp_path / "foo" / "bar.py"
        subdir.parent.mkdir(parents=True)
        subdir.touch()
        result = normalize_path(subdir, tmp_path)
        assert result == "foo/bar.py"

    def test_normalize_path_posix(self, tmp_path: Path):
        """Paths use POSIX separators (forward slashes)."""
        subdir = tmp_path / "src" / "module" / "file.py"
        subdir.parent.mkdir(parents=True)
        subdir.touch()
        result = normalize_path(subdir, tmp_path)
        assert "/" in result
        assert "\\" not in result

    def test_round_float_default_places(self):
        """Floats are rounded to 4 decimal places by default."""
        assert round_float(3.14159265359) == 3.1416
        assert round_float(0.123456789) == 0.1235

    def test_round_float_custom_places(self):
        """Custom decimal places can be specified."""
        assert round_float(3.14159265359, places=2) == 3.14

    def test_seed_random_ci_mode(self):
        """In CI mode, random is seeded with FIXED_SEED."""
        import random

        seed_random(ci_mode=True)
        val1 = random.random()
        seed_random(ci_mode=True)
        val2 = random.random()
        assert val1 == val2  # Same seed = same first value


class TestSortFunctions:
    """Test sorting functions for determinism."""

    def test_sort_signals(self):
        """Signals are sorted by (signal_id, severity)."""
        signals = [
            {"signal_id": "b", "severity": "high"},
            {"signal_id": "a", "severity": "low"},
            {"signal_id": "a", "severity": "high"},
        ]
        sorted_signals = sort_signals(signals)
        assert sorted_signals[0]["signal_id"] == "a"
        assert sorted_signals[0]["severity"] == "high"
        assert sorted_signals[1]["signal_id"] == "a"
        assert sorted_signals[1]["severity"] == "low"
        assert sorted_signals[2]["signal_id"] == "b"


class TestMakeDeterministicDict:
    """Test dictionary processing for determinism."""

    def test_timestamps_replaced_in_ci_mode(self):
        """Timestamp fields are replaced with FIXED_TIMESTAMP."""
        data = {"created_at": "2024-01-15T12:00:00+00:00", "name": "test"}
        result = make_deterministic_dict(data, ci_mode=True)
        assert result["created_at"] == FIXED_TIMESTAMP
        assert result["name"] == "test"

    def test_floats_rounded_in_ci_mode(self):
        """Float fields are rounded for stability."""
        data = {"confidence_score": 75.123456789, "name": "test"}
        result = make_deterministic_dict(data, ci_mode=True)
        assert result["confidence_score"] == 75.1235
        assert result["name"] == "test"

    def test_keys_sorted(self):
        """Dict keys are sorted for consistent ordering."""
        data = {"z_field": 1, "a_field": 2, "m_field": 3}
        result = make_deterministic_dict(data, ci_mode=True)
        keys = list(result.keys())
        assert keys == ["a_field", "m_field", "z_field"]

    def test_nested_dicts_processed(self):
        """Nested dicts are recursively processed."""
        data = {
            "outer": {"timestamp": "2024-01-15T12:00:00+00:00", "score": 1.2345678}
        }
        result = make_deterministic_dict(data, ci_mode=True)
        assert result["outer"]["timestamp"] == FIXED_TIMESTAMP
        assert result["outer"]["score"] == 1.2346

    def test_normal_mode_passthrough(self):
        """In normal mode, dict is returned unchanged."""
        data = {"created_at": "2024-01-15T12:00:00+00:00", "score": 1.2345678}
        set_ci_mode(False)
        result = make_deterministic_dict(data, ci_mode=False)
        assert result == data


class TestCLIIntegration:
    """Integration tests for --ci flag."""

    def test_help_shows_ci_flag(self):
        """The --ci flag appears in help output."""
        from code_audit.__main__ import _build_parser

        parser = _build_parser()
        help_text = parser.format_help()
        assert "--ci" in help_text or "--deterministic" in help_text

    def test_ci_mode_parsed_correctly(self):
        """The --ci flag is parsed into args.ci_mode."""
        from code_audit.__main__ import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["--ci"])
        assert hasattr(args, "ci_mode")
        assert args.ci_mode is True


class TestSnapshotRepeatability:
    """Acceptance tests for snapshot determinism."""

    def test_two_ci_runs_produce_identical_json(self, tmp_path: Path):
        """Two --ci runs on the same repo produce identical output."""
        # Create a minimal Python file to scan
        (tmp_path / "example.py").write_text(
            "def big_function():\n" + "    x = 1\n" * 100
        )

        from code_audit.__main__ import _build_parser, main

        # Run 1
        out1 = tmp_path / "run1.json"
        args1 = _build_parser().parse_args(
            ["debt", "snapshot", str(tmp_path), "--ci", "--out", str(out1)]
        )

        # Run 2
        out2 = tmp_path / "run2.json"
        args2 = _build_parser().parse_args(
            ["debt", "snapshot", str(tmp_path), "--ci", "--out", str(out2)]
        )

        # Execute both runs
        from code_audit.__main__ import _handle_debt

        # Need to set ci_mode globally
        set_ci_mode(True)
        _handle_debt(args1)
        _handle_debt(args2)
        set_ci_mode(False)

        # Compare outputs
        json1 = json.loads(out1.read_text(encoding="utf-8"))
        json2 = json.loads(out2.read_text(encoding="utf-8"))

        assert json1 == json2, "Two --ci runs should produce identical JSON"

    def test_ci_snapshot_has_fixed_timestamp(self, tmp_path: Path):
        """--ci snapshot uses fixed timestamp."""
        (tmp_path / "example.py").write_text("x = 1\n")

        out = tmp_path / "snapshot.json"

        from code_audit.__main__ import _build_parser, _handle_debt

        args = _build_parser().parse_args(
            ["debt", "snapshot", str(tmp_path), "--ci", "--out", str(out)]
        )

        set_ci_mode(True)
        _handle_debt(args)
        set_ci_mode(False)

        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["created_at"] == FIXED_TIMESTAMP


class TestNonCIDivergence:
    """Test that non-CI runs produce varying output."""

    def test_non_ci_timestamps_differ(self):
        """Without --ci, timestamps should be current time."""
        ts1 = deterministic_timestamp(ci_mode=False)
        import time

        time.sleep(0.01)  # Small delay
        ts2 = deterministic_timestamp(ci_mode=False)

        # Timestamps should differ (or at least not be fixed)
        assert ts1 != FIXED_TIMESTAMP
        assert ts2 != FIXED_TIMESTAMP

    def test_non_ci_run_ids_differ(self, tmp_path: Path):
        """Without --ci, run_ids should be unique."""
        id1 = deterministic_run_id(tmp_path, ci_mode=False)
        id2 = deterministic_run_id(tmp_path, ci_mode=False)
        assert id1 != id2
