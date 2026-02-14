"""Parity test: API scan_project equals CLI scan output under --ci.

Validates that the CLI and API produce byte-identical artifacts for the
``scan`` subcommand and default positional mode when running under
deterministic (--ci) mode.  This is the canonical proof that there is
exactly one compute path.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from code_audit.api import scan_project
from code_audit.utils.json_norm import stable_json_dumps

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "repos" / "clean_project"


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["CODE_AUDIT_DETERMINISTIC"] = "1"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return env


# ── scan subcommand parity ──────────────────────────────────────────


class TestScanSubcommandParity:
    """CLI ``scan --ci`` and API ``scan_project(ci_mode=True)`` produce
    identical JSON artifacts."""

    def test_scan_subcommand_json_matches_api(self, tmp_path: Path) -> None:
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE, work)
        (work / "artifacts").mkdir(parents=True, exist_ok=True)

        out_file = work / "artifacts" / "run_result.json"
        cmd = [
            sys.executable, "-m", "code_audit",
            "scan",
            "--root", ".",
            "--out", str(Path("artifacts") / "run_result.json"),
            "--ci",
        ]
        r = subprocess.run(cmd, cwd=str(work), env=_cli_env(), text=True, capture_output=True)
        assert r.returncode in (0, 1, 2), (
            f"CLI scan failed with exit {r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )

        cli_bytes = out_file.read_text(encoding="utf-8")

        # API scan
        _, api_dict = scan_project(work, ci_mode=True)
        api_bytes = stable_json_dumps(api_dict, ci_mode=True)

        assert cli_bytes == api_bytes, (
            "CLI scan --ci output differs from API scan_project(ci_mode=True).\n"
            "This means there are two different compute paths — fix __main__.py "
            "to delegate to code_audit.api.scan_project."
        )


# ── default positional mode parity ──────────────────────────────────


class TestDefaultPositionalParity:
    """CLI ``code-audit <path> --ci --json`` and API ``scan_project(ci_mode=True)``
    produce identical JSON output."""

    def test_default_mode_json_matches_api(self, tmp_path: Path) -> None:
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE, work)

        cmd = [
            sys.executable, "-m", "code_audit",
            str(work),
            "--ci",
            "--json",
        ]
        r = subprocess.run(cmd, env=_cli_env(), text=True, capture_output=True)
        assert r.returncode in (0, 1, 2), (
            f"CLI default mode failed with exit {r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )

        cli_bytes = r.stdout

        # API scan
        _, api_dict = scan_project(work, ci_mode=True)
        api_bytes = stable_json_dumps(api_dict, ci_mode=True, indent=2)

        assert cli_bytes == api_bytes, (
            "CLI default mode --ci --json output differs from API scan_project.\n"
            "This means there are two different compute paths."
        )

    def test_default_and_scan_subcommand_produce_same_result(
        self, tmp_path: Path
    ) -> None:
        """Both CLI modes must produce functionally identical data."""
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE, work)
        (work / "artifacts").mkdir(parents=True, exist_ok=True)

        # Default positional mode
        cmd_default = [
            sys.executable, "-m", "code_audit",
            str(work),
            "--ci",
            "--json",
        ]
        r1 = subprocess.run(cmd_default, env=_cli_env(), text=True, capture_output=True)
        assert r1.returncode in (0, 1, 2)

        # Scan subcommand
        out_file = work / "artifacts" / "scan.json"
        cmd_scan = [
            sys.executable, "-m", "code_audit",
            "scan",
            "--root", str(work),
            "--out", str(out_file),
            "--ci",
        ]
        r2 = subprocess.run(cmd_scan, env=_cli_env(), text=True, capture_output=True)
        assert r2.returncode in (0, 1, 2)

        # Compare (ignoring config.root which may differ)
        default_dict = json.loads(r1.stdout)
        scan_dict = json.loads(out_file.read_text(encoding="utf-8"))

        # Normalize config.root which differs by invocation
        default_dict.get("run", {}).get("config", {}).pop("root", None)
        scan_dict.get("run", {}).get("config", {}).pop("root", None)

        assert default_dict == scan_dict, (
            "Default positional mode and scan subcommand produce different results."
        )
