"""CI-guard enforcement: supported commands must be run with --ci under CI=true."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _copy_tree(src: Path, dst: Path) -> None:
    for p in src.rglob("*"):
        rel = p.relative_to(src)
        out = dst / rel
        if p.is_dir():
            out.mkdir(parents=True, exist_ok=True)
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(p.read_bytes())


def test_ci_env_requires_ci_flag_for_debt_snapshot(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    fixture_repo = repo_root / "tests" / "fixtures" / "repos" / "clean_project"
    assert fixture_repo.exists(), f"Missing fixture: {fixture_repo}"

    workdir = tmp_path / "repo"
    workdir.mkdir(parents=True)
    _copy_tree(fixture_repo, workdir)

    # Avoid false failures if snapshot doesn't mkdir parents
    (workdir / "artifacts").mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["CI"] = "true"
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONPATH"] = str(repo_root / "src")

    # No --ci => must fail with exit code 2 and exact stderr
    cmd = [
        sys.executable,
        "-m",
        "code_audit",
        "debt",
        "snapshot",
        ".",
        "--out",
        "artifacts/current.json",
    ]
    p = subprocess.run(cmd, cwd=str(workdir), env=env, capture_output=True, text=True)

    assert p.returncode == 2, (p.stdout, p.stderr)
    assert p.stdout == ""
    assert (
        p.stderr.strip()
        == "error: CI environment requires deterministic mode for debt snapshot. Re-run with --ci/--deterministic."
    )
