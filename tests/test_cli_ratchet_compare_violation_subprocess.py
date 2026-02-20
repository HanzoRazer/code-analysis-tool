"""End-to-end ratchet violation test via subprocess.

Creates a clean baseline, introduces intentional new structural debt
(a god_function with >60 lines), then asserts ``debt compare`` returns
exit code 1 (ratchet violation).

This catches cases where determinism hooks are wired in the Python API
but forgotten in the CLI path.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


@pytest.mark.integration
def test_debt_compare_returns_1_on_new_debt(tmp_path: Path) -> None:
    """End-to-end ratchet check using the real CLI."""

    fixture_src = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"
    assert fixture_src.exists(), f"Missing fixture repo: {fixture_src}"

    # Work in an isolated copy of the fixture repo.
    work = tmp_path / "proj"
    shutil.copytree(fixture_src, work)

    (work / "artifacts").mkdir(parents=True, exist_ok=True)

    # Ensure subprocess can import the in-repo package.
    env = dict(os.environ)
    src_dir = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        [src_dir, env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)
    env["PYTHONHASHSEED"] = "0"
    env["CI"] = "true"

    baseline_path = work / "artifacts" / "baseline.json"
    current_path = work / "artifacts" / "current.json"

    # Baseline snapshot (deterministic).
    p1 = _run(
        [
            sys.executable, "-m", "code_audit",
            "debt", "snapshot", ".",
            "--ci", "--out", str(baseline_path.relative_to(work)),
        ],
        cwd=work,
        env=env,
    )
    assert p1.returncode == 0, f"baseline snapshot failed\nSTDERR:\n{p1.stderr}\nSTDOUT:\n{p1.stdout}"
    assert baseline_path.exists()

    # Introduce intentional new structural debt: a god_function (>60 lines).
    bad = work / "src" / "introduced_debt.py"
    bad.parent.mkdir(parents=True, exist_ok=True)
    lines = ["def huge():"] + ["    x = 0" for _ in range(65)] + ["    return x", ""]
    bad.write_text("\n".join(lines), encoding="utf-8")

    p2 = _run(
        [
            sys.executable, "-m", "code_audit",
            "debt", "snapshot", ".",
            "--ci", "--out", str(current_path.relative_to(work)),
        ],
        cwd=work,
        env=env,
    )
    assert p2.returncode == 0, f"current snapshot failed\nSTDERR:\n{p2.stderr}\nSTDOUT:\n{p2.stdout}"
    assert current_path.exists()

    # Compare should fail the ratchet gate (exit 1) because new debt was introduced.
    p3 = _run(
        [
            sys.executable, "-m", "code_audit",
            "debt", "compare", ".",
            "--baseline", str(baseline_path.relative_to(work)),
            "--current", str(current_path.relative_to(work)),
            "--ci", "--json",
        ],
        cwd=work,
        env=env,
    )

    assert p3.returncode == 1, (
        "expected ratchet violation exit code 1\n"
        f"STDERR:\n{p3.stderr}\nSTDOUT:\n{p3.stdout}"
    )
