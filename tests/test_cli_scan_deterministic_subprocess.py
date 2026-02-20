"""Subprocess determinism test: ``code-audit scan --ci`` produces byte-identical output."""

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
    env["CI"] = "true"
    return subprocess.run(cmd, cwd=str(cwd), env=env, text=True, capture_output=True)


def test_cli_scan_is_byte_deterministic_under_ci(tmp_path: Path) -> None:
    """Runs ``scan --ci`` twice and asserts output files are byte-identical."""

    fixture = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"
    work = tmp_path / "repo"
    shutil.copytree(fixture, work)

    (work / "artifacts").mkdir(parents=True, exist_ok=True)

    out_a = work / "artifacts" / "run_a.json"
    out_b = work / "artifacts" / "run_b.json"

    cmd_a = [
        sys.executable,
        "-m",
        "code_audit",
        "scan",
        "--root",
        ".",
        "--out",
        str(Path("artifacts") / "run_a.json"),
        "--ci",
    ]
    cmd_b = [
        sys.executable,
        "-m",
        "code_audit",
        "scan",
        "--root",
        ".",
        "--out",
        str(Path("artifacts") / "run_b.json"),
        "--ci",
    ]

    r1 = _run(cmd_a, cwd=work)
    assert r1.returncode == 0, (r1.stdout, r1.stderr)
    r2 = _run(cmd_b, cwd=work)
    assert r2.returncode == 0, (r2.stdout, r2.stderr)

    assert out_a.read_bytes() == out_b.read_bytes()
