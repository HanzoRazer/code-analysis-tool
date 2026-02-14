#!/usr/bin/env python3
"""Refresh the committed structural debt baseline.

Developer-only helper.

Usage:
  python scripts/refresh_baseline.py

Writes:
  baselines/main.json

Safety:
  - Refuses to run if the git working tree is dirty
  - Validates generated snapshot against debt_snapshot.schema.json
  - Uses atomic file replace (write to temp, validate, then os.replace)
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINES_DIR = REPO_ROOT / "baselines"
BASELINE_FILE = BASELINES_DIR / "main.json"
SCHEMA_FILE = REPO_ROOT / "schemas" / "debt_snapshot.schema.json"

EXIT_OK = 0
EXIT_ERROR = 2


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd), env=env, capture_output=True, text=True)


def _ensure_clean_git_tree(env: dict[str, str]) -> None:
    """Fail-closed if the working tree has uncommitted changes."""
    p = _run(["git", "status", "--porcelain"], cwd=REPO_ROOT, env=env)
    if p.returncode != 0:
        msg = (p.stderr or p.stdout or "").strip()
        raise RuntimeError(f"git status failed; cannot verify clean tree. {msg}".strip())
    if p.stdout.strip():
        raise RuntimeError("working tree is dirty. Commit or stash changes before refreshing baseline.")


def main() -> int:
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)

    if not SCHEMA_FILE.exists():
        print(f"error: missing schema file: {SCHEMA_FILE}", file=sys.stderr)
        return EXIT_ERROR

    # Stabilize local refresh behavior (avoid accidental CI env bleed-through)
    env = os.environ.copy()
    env["CI"] = "0"
    env["PYTHONHASHSEED"] = "0"
    env["CODE_AUDIT_DETERMINISTIC"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")

    try:
        _ensure_clean_git_tree(env)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    # Write to a temp file first, then validate, then atomic replace.
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="baseline_tmp_",
        suffix=".json",
        dir=str(BASELINES_DIR),
        delete=False,
    ) as tf:
        tmp_path = Path(tf.name)

    try:
        # 1) Produce deterministic debt snapshot into temp file
        snap_cmd = [
            sys.executable,
            "-m",
            "code_audit",
            "debt",
            "snapshot",
            ".",
            "--ci",
            "--out",
            str(tmp_path.relative_to(REPO_ROOT)),
        ]
        p = _run(snap_cmd, cwd=REPO_ROOT, env=env)
        if p.returncode != 0:
            print("error: baseline snapshot generation failed.", file=sys.stderr)
            if p.stdout.strip():
                print(p.stdout.rstrip(), file=sys.stderr)
            if p.stderr.strip():
                print(p.stderr.rstrip(), file=sys.stderr)
            return EXIT_ERROR

        # 2) Validate snapshot schema
        val_cmd = [
            sys.executable,
            "-m",
            "code_audit",
            "validate",
            str(tmp_path.relative_to(REPO_ROOT)),
            "debt_snapshot.schema.json",
        ]
        p = _run(val_cmd, cwd=REPO_ROOT, env=env)
        if p.returncode != 0:
            print("error: generated baseline did not validate against debt_snapshot.schema.json.", file=sys.stderr)
            if p.stdout.strip():
                print(p.stdout.rstrip(), file=sys.stderr)
            if p.stderr.strip():
                print(p.stderr.rstrip(), file=sys.stderr)
            return EXIT_ERROR

        # 3) Atomic replace into baselines/main.json
        os.replace(tmp_path, BASELINE_FILE)
        print(f"baseline refreshed: {BASELINE_FILE.relative_to(REPO_ROOT)}")
        return EXIT_OK

    finally:
        # If tmp still exists (failure path), clean it up.
        try:
            if tmp_path.exists() and tmp_path != BASELINE_FILE:
                tmp_path.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
