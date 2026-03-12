"""CLI / API parity: --enable-js-ts flag produces identical output.

Mirrors test_cli_api_parity_scan_ci.py but activates multi-language analysis
so JS/TS findings flow through both the scan subcommand and the API function.
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

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "repos" / "sample_repo_js_ts_all"


def _cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["CODE_AUDIT_DETERMINISTIC"] = "1"
    env["CI"] = "true"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    return env


@pytest.mark.integration
class TestScanSubcommandParityJsTs:
    """scan subcommand with --enable-js-ts produces result identical to API."""

    def test_scan_ci_js_ts_matches_api(self, tmp_path: Path) -> None:
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE, work)
        (work / "artifacts").mkdir(parents=True, exist_ok=True)

        out_file = work / "artifacts" / "run_result.json"
        cmd = [
            sys.executable,
            "-m",
            "code_audit",
            "scan",
            "--root",
            ".",
            "--out",
            str(Path("artifacts") / "run_result.json"),
            "--ci",
        ]
        r = subprocess.run(
            cmd, cwd=str(work), env=_cli_env(), text=True, capture_output=True
        )
        assert r.returncode in (0, 1, 2), (
            f"CLI scan (JS/TS default-on) failed exit={r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )
        assert out_file.exists(), "scan --out did not create the output file"

        cli_bytes = out_file.read_text(encoding="utf-8")

        # API path
        _, api_dict = scan_project(work, ci_mode=True, enable_js_ts=True)
        api_bytes = stable_json_dumps(api_dict, ci_mode=True)

        assert cli_bytes == api_bytes, (
            "CLI scan --enable-js-ts --ci output differs from "
            "scan_project(enable_js_ts=True).\n"
            "This means there are two different compute paths."
        )

    def test_js_ts_findings_present(self, tmp_path: Path) -> None:
        """Sanity: when --enable-js-ts is on, JS/TS findings are non-empty."""
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE, work)
        (work / "artifacts").mkdir(parents=True, exist_ok=True)

        out_file = work / "artifacts" / "run_result.json"
        cmd = [
            sys.executable,
            "-m",
            "code_audit",
            "scan",
            "--root",
            ".",
            "--out",
            str(Path("artifacts") / "run_result.json"),
            "--ci",
        ]
        r = subprocess.run(
            cmd, cwd=str(work), env=_cli_env(), text=True, capture_output=True
        )
        assert r.returncode in (0, 1, 2)

        result = json.loads(out_file.read_text(encoding="utf-8"))
        findings = result.get("findings_raw", [])
        js_ts_findings = [
            f
            for f in findings
            if f.get("type") == "js_ts_security"
        ]
        assert len(js_ts_findings) > 0, (
            "Expected at least one js_ts_security finding with --enable-js-ts"
        )


@pytest.mark.integration
class TestDefaultPositionalParityJsTs:
    """Default positional mode with --enable-js-ts matches API."""

    def test_default_mode_js_ts_matches_api(self, tmp_path: Path) -> None:
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE, work)

        cmd = [
            sys.executable,
            "-m",
            "code_audit",
            str(work),
            "--ci",
            "--json",
        ]
        r = subprocess.run(
            cmd, env=_cli_env(), encoding="utf-8", capture_output=True
        )
        assert r.returncode in (0, 1, 2), (
            f"CLI default (JS/TS default-on) failed exit={r.returncode}\n"
            f"stdout: {r.stdout}\nstderr: {r.stderr}"
        )

        cli_bytes = r.stdout

        # API scan
        _, api_dict = scan_project(work, ci_mode=True, enable_js_ts=True)
        api_bytes = stable_json_dumps(api_dict, ci_mode=True, indent=2)

        assert cli_bytes == api_bytes, (
            "CLI default mode --enable-js-ts --ci --json output differs from "
            "scan_project(enable_js_ts=True).\n"
            "This means there are two different compute paths."
        )

    def test_default_and_scan_subcommand_agree(self, tmp_path: Path) -> None:
        """Both CLI modes with --enable-js-ts produce identical data."""
        work = tmp_path / "repo"
        shutil.copytree(FIXTURE, work)
        (work / "artifacts").mkdir(parents=True, exist_ok=True)

        # Default positional mode
        cmd_default = [
            sys.executable,
            "-m",
            "code_audit",
            str(work),
            "--ci",
            "--json",
        ]
        r1 = subprocess.run(
            cmd_default, env=_cli_env(), encoding="utf-8", capture_output=True
        )
        assert r1.returncode in (0, 1, 2)

        # Scan subcommand
        out_file = work / "artifacts" / "run_result.json"
        cmd_scan = [
            sys.executable,
            "-m",
            "code_audit",
            "scan",
            "--root",
            ".",
            "--out",
            str(Path("artifacts") / "run_result.json"),
            "--ci",
        ]
        r2 = subprocess.run(
            cmd_scan, cwd=str(work), env=_cli_env(), text=True, capture_output=True
        )
        assert r2.returncode in (0, 1, 2)

        # Compare (ignoring config.root which may differ by invocation)
        default_dict = json.loads(r1.stdout)
        scan_dict = json.loads(out_file.read_text(encoding="utf-8"))

        default_dict.get("run", {}).get("config", {}).pop("root", None)
        scan_dict.get("run", {}).get("config", {}).pop("root", None)

        assert default_dict == scan_dict, (
            "Default positional and scan subcommand with --enable-js-ts "
            "produce different results."
        )
