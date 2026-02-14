"""Subprocess determinism test: ``code-audit <path> --ci --json`` produces byte-identical stdout."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["CODE_AUDIT_DETERMINISTIC"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)


def test_cli_default_positional_mode_is_byte_deterministic_under_ci(tmp_path: Path) -> None:
    """Default positional mode (``code-audit <path> --ci --json``) must be byte-deterministic."""

    fixture = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"
    work = tmp_path / "repo"
    shutil.copytree(fixture, work)

    cmd = [
        sys.executable,
        "-m",
        "code_audit",
        ".",
        "--ci",
        "--json",
    ]

    r1 = _run(cmd, cwd=work)
    assert r1.returncode == 0, (r1.stdout, r1.stderr)
    r2 = _run(cmd, cwd=work)
    assert r2.returncode == 0, (r2.stdout, r2.stderr)

    assert r1.stdout.encode("utf-8") == r2.stdout.encode("utf-8")
