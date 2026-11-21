"""build_run_result must not crash on a tree with no exception findings.

A clean tree (no broad/swallowed excepts) is the common case. The legacy
signal builder indexed the first exception finding unconditionally, so it
raised IndexError there.
"""

from __future__ import annotations

import warnings
from pathlib import Path

from code_audit.run_result import _build_signals_snapshot, build_run_result


def test_signals_snapshot_with_no_findings_is_empty() -> None:
    assert _build_signals_snapshot(findings=[]) == []


def test_build_run_result_on_clean_tree(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        result = build_run_result(root=str(tmp_path), tool_version="test")

    assert result["signals_snapshot"] == []
    assert result["summary"]["counts"]["findings_total"] == 0
    assert result["scan_integrity"]["assessable"] is True
    assert result["summary"]["vibe_tier"] != "inconclusive"
