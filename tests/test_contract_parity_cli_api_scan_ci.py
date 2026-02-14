"""Contract parity: CLI scan output == API scan output under --ci.

Level 3 parity test.  Any hidden compute or serialization divergence
in the CLI will break byte-identity immediately.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from code_audit.api import scan_project
from code_audit.utils.json_norm import stable_json_dumps

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SRC = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["CODE_AUDIT_DETERMINISTIC"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return env


def _norm(b: bytes) -> bytes:
    """Normalize CRLF → LF for cross-platform byte comparison."""
    return b.replace(b"\r\n", b"\n")


def test_contract_parity_scan_default_positional_ci(tmp_path: Path) -> None:
    """CLI default positional --ci --json stdout == API scan_project(ci_mode=True)."""
    workdir = tmp_path / "repo"
    shutil.copytree(FIXTURE_SRC, workdir)

    # API (canonical)
    _, api_dict = scan_project(workdir, ci_mode=True)
    api_bytes = stable_json_dumps(api_dict, indent=2, ci_mode=True).encode("utf-8")

    # CLI default positional
    p = subprocess.run(
        [sys.executable, "-m", "code_audit", str(workdir), "--ci", "--json"],
        env=_cli_env(),
        capture_output=True,
    )
    assert p.returncode in (0, 1), (p.stdout, p.stderr)
    assert _norm(api_bytes) == _norm(p.stdout)


def test_contract_parity_scan_subcommand_ci(tmp_path: Path) -> None:
    """CLI scan --ci --out file == API scan_project(ci_mode=True)."""
    workdir = tmp_path / "repo"
    shutil.copytree(FIXTURE_SRC, workdir)

    # API (canonical)
    _, api_dict = scan_project(workdir, ci_mode=True)
    api_bytes = stable_json_dumps(api_dict, ci_mode=True).encode("utf-8")

    # CLI scan subcommand writes to --out file
    out_file = tmp_path / "result.json"
    p = subprocess.run(
        [
            sys.executable, "-m", "code_audit",
            "scan", "--root", str(workdir),
            "--out", str(out_file),
            "--ci",
        ],
        env=_cli_env(),
        capture_output=True,
    )
    assert p.returncode in (0, 1), (p.stdout, p.stderr)
    assert _norm(api_bytes) == _norm(out_file.read_bytes())


def test_contract_default_and_subcommand_produce_same_result(tmp_path: Path) -> None:
    """Both CLI modes produce the same scan result (after normalizing config.root)."""
    workdir = tmp_path / "repo"
    shutil.copytree(FIXTURE_SRC, workdir)

    # Default positional
    p1 = subprocess.run(
        [sys.executable, "-m", "code_audit", str(workdir), "--ci", "--json"],
        env=_cli_env(),
        capture_output=True,
    )
    assert p1.returncode in (0, 1)

    # Scan subcommand
    out_file = tmp_path / "scan_result.json"
    p2 = subprocess.run(
        [
            sys.executable, "-m", "code_audit",
            "scan", "--root", str(workdir),
            "--out", str(out_file),
            "--ci",
        ],
        env=_cli_env(),
        capture_output=True,
    )
    assert p2.returncode in (0, 1)

    import json
    d1 = json.loads(p1.stdout)
    d2 = json.loads(out_file.read_text(encoding="utf-8"))

    # config.root may differ in representation; normalize for comparison
    d1.get("config", {}).pop("root", None)
    d2.get("config", {}).pop("root", None)

    assert d1 == d2
