"""Schema version freeze — canonical schemas only.

Canonical location: ``src/code_audit/data/schemas/``
Stale duplicate ``code_audit/data/schemas/`` must not exist.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from code_audit.model.run_result import RunResult

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "src" / "code_audit" / "data" / "schemas"


def _schema_files() -> list[Path]:
    assert SCHEMA_DIR.exists(), f"Missing canonical schema dir: {SCHEMA_DIR}"
    return sorted(SCHEMA_DIR.glob("*.schema.json"))


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _schema_version_const(schema: dict) -> str:
    return str(
        schema.get("properties", {})
        .get("schema_version", {})
        .get("const", "")
    ).strip()


# ------------------------------------------------------------------
# 1) Every canonical schema must declare schema_version.const
# ------------------------------------------------------------------


def test_all_canonical_schema_files_have_schema_version_const() -> None:
    files = _schema_files()
    assert files, f"No schema files found in {SCHEMA_DIR}"

    for p in files:
        schema = _load_json(p)
        const = _schema_version_const(schema)
        assert const, f"{p.name} missing properties.schema_version.const"
        assert re.fullmatch(r"[a-z0-9_]+_v[0-9]+", const), (
            f"{p.name} has unexpected schema_version.const: {const!r}"
        )


# ------------------------------------------------------------------
# 2) RunResult.to_dict().schema_version matches the schema const
# ------------------------------------------------------------------


def test_run_result_schema_version_matches_RunResult_to_dict() -> None:
    schema_path = SCHEMA_DIR / "run_result.schema.json"
    assert schema_path.exists(), f"Missing {schema_path}"

    schema = _load_json(schema_path)
    expected = _schema_version_const(schema)
    assert expected, f"{schema_path.name} missing schema_version.const"

    rr = RunResult()
    out = rr.to_dict()
    assert out["schema_version"] == expected


# ------------------------------------------------------------------
# 3) Stale duplicate directory must not exist
# ------------------------------------------------------------------


def test_no_stale_schema_duplicate_directory() -> None:
    # Canonical is src/code_audit/data/schemas.
    # This directory is known-stale and should not exist.
    stale = REPO_ROOT / "code_audit" / "data" / "schemas"
    assert not stale.exists(), (
        f"Stale duplicate schema dir must be removed: {stale}"
    )


# ------------------------------------------------------------------
# 4) debt_snapshot contract alignment
# ------------------------------------------------------------------


def test_debt_snapshot_schema_version_matches_api_if_present() -> None:
    from code_audit.api import snapshot_debt

    schema_path = SCHEMA_DIR / "debt_snapshot.schema.json"
    if not schema_path.exists():
        pytest.skip("debt_snapshot schema not present")

    schema = _load_json(schema_path)
    expected = _schema_version_const(schema)
    assert expected

    fixture = Path("tests/fixtures/repos/clean_project")
    if not fixture.exists():
        pytest.skip("missing tests/fixtures/repos/clean_project")

    out = snapshot_debt(fixture.resolve(), ci_mode=True)
    assert out["schema_version"] == expected
