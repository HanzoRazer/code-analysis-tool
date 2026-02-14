"""Test: refresh_baseline.py refuses to run on a dirty git tree.

Mocks git to report dirty status and verifies the script exits 2
without overwriting the baseline file.
"""

from __future__ import annotations

import runpy
import subprocess
from pathlib import Path

import pytest


def test_refresh_baseline_refuses_dirty_tree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Script must exit 2 and leave baseline untouched when git tree is dirty."""
    # Arrange: isolated fake repo layout
    repo_root = tmp_path
    (repo_root / "baselines").mkdir()
    (repo_root / "schemas").mkdir()
    (repo_root / "schemas" / "debt_snapshot.schema.json").write_text("{}", encoding="utf-8")

    baseline = repo_root / "baselines" / "main.json"
    sentinel = '{"schema_version":"debt_snapshot_v1"}'
    baseline.write_text(sentinel, encoding="utf-8")

    script_path = Path(__file__).resolve().parents[1] / "scripts" / "refresh_baseline.py"
    assert script_path.exists(), "scripts/refresh_baseline.py must exist"

    # Mock subprocess.run: git status returns dirty; nothing else should run.
    def fake_run(cmd, cwd=None, env=None, capture_output=None, text=None):
        if cmd[:3] == ["git", "status", "--porcelain"]:
            return subprocess.CompletedProcess(
                cmd, 0, stdout=" M src/code_audit/__main__.py\n", stderr=""
            )
        # If anything beyond git is attempted, fail — dirty tree should short-circuit.
        return subprocess.CompletedProcess(cmd, 99, stdout="", stderr="unexpected subprocess call")

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Load script as module, patch its constants to point at tmp layout.
    ns = runpy.run_path(str(script_path))
    ns["REPO_ROOT"] = repo_root
    ns["BASELINES_DIR"] = repo_root / "baselines"
    ns["BASELINE_FILE"] = baseline
    ns["SCHEMA_FILE"] = repo_root / "schemas" / "debt_snapshot.schema.json"

    main_fn = ns["main"]
    main_fn.__globals__.update(ns)

    rc = main_fn()

    assert rc == 2, f"Expected exit 2 (error), got {rc}"
    assert baseline.read_text(encoding="utf-8") == sentinel, "Baseline must NOT be overwritten"
