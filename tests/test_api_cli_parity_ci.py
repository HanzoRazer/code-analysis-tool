# tests/test_api_cli_parity_ci.py
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from code_audit.api import scan_project
from code_audit.utils.json_norm import stable_json_dumps


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _fixture_repo(name: str) -> Path:
    p = _repo_root() / "tests" / "fixtures" / "repos" / name
    assert p.exists(), f"fixture repo missing: {p}"
    return p


def _run_cli_scan_json(root: Path) -> dict[str, Any]:
    """
    Run real CLI via subprocess and parse stdout as JSON.
    Uses --ci to force determinism. Under CI-required envs, this also prevents guard failure.
    """
    env = os.environ.copy()

    # Keep parity tests stable even if a CI guard checks env.
    env.setdefault("CODE_AUDIT_DETERMINISTIC", "1")
    env.setdefault("PYTHONHASHSEED", "0")
    # The --ci flag now requires CI=true in the environment.
    env["CI"] = "true"

    cmd = [sys.executable, "-m", "code_audit", str(root), "--json", "--ci"]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env)

    assert proc.returncode in (0, 1, 2), (
        f"CLI error (exit {proc.returncode}): {' '.join(cmd)}\n"
        f"stdout:\n{proc.stdout}\n"
        f"stderr:\n{proc.stderr}"
    )

    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise AssertionError(
            f"CLI stdout was not JSON\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        ) from e

    assert isinstance(out, dict), f"CLI JSON root must be dict, got {type(out)}"
    return out


def _run_api_scan_json(root: Path) -> dict[str, Any]:
    """
    Run API directly and return the schema-shaped dict.
    scan_project returns (RunResult, dict); we compare the dict only.
    """
    _, d = scan_project(str(root), ci_mode=True)
    assert isinstance(d, dict)
    return d


def _strip_known_volatiles(d: dict[str, Any]) -> dict[str, Any]:
    """
    In CI mode these should already be deterministic.
    This function is intentionally minimal:
      - if a future change reintroduces volatility, add the smallest possible strip here
        *only* for fields that are not part of the contract.
    """
    # Defensive copy (avoid mutating inputs)
    return json.loads(stable_json_dumps(d))


def test_api_cli_parity_ci_default_scan_sample_repo_exceptions() -> None:
    """
    Contract test: CLI default scan output == API scan output in deterministic mode.

    This catches:
      - CLI forgetting to pass ci_mode through the stack
      - CLI reshaping/mutating the API dict
      - differing ordering/normalization between CLI and API
      - accidental duplicate compute paths that drift
    """
    root = _fixture_repo("sample_repo_exceptions")

    cli_dict = _strip_known_volatiles(_run_cli_scan_json(root))
    api_dict = _strip_known_volatiles(_run_api_scan_json(root))

    # Byte-identical comparison using repo's stable JSON serializer.
    cli_s = stable_json_dumps(cli_dict)
    api_s = stable_json_dumps(api_dict)

    assert cli_s == api_s, (
        "API/CLI parity failure (default scan, --ci).\n"
        "Tip: diff the two JSON strings to find the first drift.\n"
        f"CLI:\n{cli_s}\n\nAPI:\n{api_s}\n"
    )
