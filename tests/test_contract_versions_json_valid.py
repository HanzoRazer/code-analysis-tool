"""Test: contracts/versions.json is valid and consistent.

Validates:
1. versions.json exists and is valid JSON.
2. Conforms to contracts_versions.schema.json.
3. signal_logic_version matches RunResult default.
4. Python accessor module loads correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

_REPO = Path(__file__).resolve().parents[1]
_VERSIONS_JSON = _REPO / "src" / "code_audit" / "contracts" / "versions.json"
_SCHEMA = _REPO / "schemas" / "contracts_versions.schema.json"


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def test_versions_json_exists():
    assert _VERSIONS_JSON.exists(), (
        f"Missing: {_VERSIONS_JSON}\n"
        "contracts/versions.json is the governance single source of truth."
    )


def test_versions_json_valid_json():
    data = _load_json(_VERSIONS_JSON)
    assert isinstance(data, dict)
    assert "signal_logic_version" in data


def test_versions_json_conforms_to_schema():
    data = _load_json(_VERSIONS_JSON)
    schema = _load_json(_SCHEMA)
    jsonschema.validate(instance=data, schema=schema)


def test_signal_logic_version_matches_run_result_default():
    """versions.json signal_logic_version must equal RunResult.signal_logic_version default."""
    data = _load_json(_VERSIONS_JSON)
    from code_audit.model.run_result import RunResult

    rr = RunResult()
    assert rr.signal_logic_version == data["signal_logic_version"], (
        f"Mismatch: RunResult default is {rr.signal_logic_version!r}, "
        f"versions.json has {data['signal_logic_version']!r}.\n"
        "Keep them in sync. versions.json is the single source of truth."
    )


def test_python_accessor_loads():
    """The Python accessor module returns the correct value."""
    from code_audit.contracts.versions import signal_logic_version

    data = _load_json(_VERSIONS_JSON)
    assert signal_logic_version() == data["signal_logic_version"]
