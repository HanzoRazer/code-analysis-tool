"""Subprocess-based determinism test: two --ci debt snapshots must be byte-identical.

This test runs the real CLI through ``subprocess`` (so PATH, PYTHONPATH,
and all process-level state are exercised) and asserts that the output
files are bit-for-bit identical.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_cli(*args: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "code_audit", *args],
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
    )


def test_ci_debt_snapshot_is_byte_identical_via_subprocess(tmp_path: Path) -> None:
    """Run the CLI twice and assert byte-identical debt snapshots under --ci."""

    fixture_src = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"

    project = tmp_path / "project"
    shutil.copytree(fixture_src, project)
    (project / "artifacts").mkdir(parents=True, exist_ok=True)

    out_a = project / "artifacts" / "current_a.json"
    out_b = project / "artifacts" / "current_b.json"

    env = os.environ.copy()
    # Ensure the package is discoverable from the fixture directory.
    src_dir = str(REPO_ROOT / "src")
    env["PYTHONPATH"] = os.pathsep.join(
        [src_dir, env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)
    env["PYTHONHASHSEED"] = "0"
    env["CI"] = "true"

    cmd_a = ("debt", "snapshot", ".", "--ci", "--out", "artifacts/current_a.json")
    r1 = _run_cli(*cmd_a, cwd=project, env=env)
    assert r1.returncode == 0, f"stderr:\n{r1.stderr}\nstdout:\n{r1.stdout}"

    cmd_b = ("debt", "snapshot", ".", "--ci", "--out", "artifacts/current_b.json")
    r2 = _run_cli(*cmd_b, cwd=project, env=env)
    assert r2.returncode == 0, f"stderr:\n{r2.stderr}\nstdout:\n{r2.stdout}"

    a_bytes = out_a.read_bytes()
    b_bytes = out_b.read_bytes()
    assert a_bytes == b_bytes, "Two --ci snapshots must be byte-identical"
