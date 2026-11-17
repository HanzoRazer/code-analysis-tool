"""Debt CLI contract parity.

Locks the flags and the CI guard. A future change that drops ``--ci`` or
``--out``, or that stops requiring ``--ci`` when CI is set, fails here.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def test_debt_snapshot_declares_ci_and_out() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "code_audit", "debt", "snapshot", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    help_text = completed.stdout
    assert "--ci" in help_text
    assert "--out" in help_text
    assert "--name" in help_text


def test_debt_compare_declares_baseline_and_ci() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "code_audit", "debt", "compare", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    help_text = completed.stdout
    assert "--baseline" in help_text
    assert "--ci" in help_text


def test_debt_snapshot_still_requires_ci_when_ci_env_set(tmp_path: Path) -> None:
    (tmp_path / "mod.py").write_text("x = 1\n")
    (tmp_path / "artifacts").mkdir()
    env = os.environ.copy()
    env["CI"] = "true"
    env["PYTHONHASHSEED"] = "0"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "code_audit",
            "debt",
            "snapshot",
            ".",
            "--out",
            "artifacts/current.json",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr.strip() == (
        "error: CI environment requires deterministic mode for debt snapshot. "
        "Re-run with --ci/--deterministic."
    )
