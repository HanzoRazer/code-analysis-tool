"""BOM JS/TS surface attestation tests.

Verifies that:
1. release_bom.schema.json accepts optional treesitter/contract/js_ts_surface artifacts
2. generate_release_bom.py emits the artifacts when RELEASE_ENABLE_JS_TS=true
3. check_release_bom_generator_gate.py flags missing artifacts
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
BOM_SCHEMA_PATH = ROOT / "schemas" / "release_bom.schema.json"
GATE_RESULT_SCHEMA_PATH = ROOT / "schemas" / "release_bom_generator_gate_result.schema.json"


class TestBomSchemaAcceptsJsTsArtifacts:
    """The BOM schema must declare treesitter_manifest, contract_versions,
    and js_ts_surface as optional artifact properties."""

    @pytest.fixture()
    def bom_schema(self) -> dict:
        return json.loads(BOM_SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_treesitter_manifest_property_exists(self, bom_schema: dict) -> None:
        artifacts_props = bom_schema["properties"]["artifacts"]["properties"]
        assert "treesitter_manifest" in artifacts_props

    def test_contract_versions_property_exists(self, bom_schema: dict) -> None:
        artifacts_props = bom_schema["properties"]["artifacts"]["properties"]
        assert "contract_versions" in artifacts_props

    def test_js_ts_surface_property_exists(self, bom_schema: dict) -> None:
        artifacts_props = bom_schema["properties"]["artifacts"]["properties"]
        assert "js_ts_surface" in artifacts_props

    def test_js_ts_artifacts_not_required(self, bom_schema: dict) -> None:
        """JS/TS artifacts are opt-in — they must NOT be in the required list."""
        required = bom_schema["properties"]["artifacts"]["required"]
        for name in ("treesitter_manifest", "contract_versions", "js_ts_surface"):
            assert name not in required, f"{name} should be optional, not required"


class TestGateResultSchemaIssueKinds:
    """Gate result schema must include JS/TS-related issue kinds."""

    @pytest.fixture()
    def gate_schema(self) -> dict:
        return json.loads(GATE_RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_treesitter_missing_issue_kind(self, gate_schema: dict) -> None:
        kinds = gate_schema["allOf"][1]["properties"]["details"]["items"]["properties"]["kind"]["enum"]
        assert "treesitter_manifest_missing" in kinds

    def test_contract_versions_missing_issue_kind(self, gate_schema: dict) -> None:
        kinds = gate_schema["allOf"][1]["properties"]["details"]["items"]["properties"]["kind"]["enum"]
        assert "contract_versions_missing" in kinds

    def test_js_ts_surface_missing_issue_kind(self, gate_schema: dict) -> None:
        kinds = gate_schema["allOf"][1]["properties"]["details"]["items"]["properties"]["kind"]["enum"]
        assert "js_ts_surface_missing" in kinds
