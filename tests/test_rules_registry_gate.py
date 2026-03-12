"""Rules Registry Gate — validates registry schema, version alignment, and hash integrity."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "src" / "code_audit" / "contracts" / "rules_registry.json"
SCHEMA = ROOT / "schemas" / "rules_registry.schema.json"
VERSIONS = ROOT / "src" / "code_audit" / "contracts" / "versions.json"


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _signal_logic_version() -> str:
    obj = _load_json(VERSIONS)
    v = obj.get("signal_logic_version")
    assert isinstance(v, str) and v.startswith("signals_v")
    return v


def test_rules_registry_validates_schema() -> None:
    assert REGISTRY.exists(), "Missing src/code_audit/contracts/rules_registry.json"
    assert SCHEMA.exists(), "Missing schemas/rules_registry.schema.json"
    jsonschema.validate(instance=_load_json(REGISTRY), schema=_load_json(SCHEMA))


def test_rules_registry_aligns_with_version_anchor() -> None:
    reg = _load_json(REGISTRY)
    assert reg.get("signal_logic_version") == _signal_logic_version(), (
        "rules_registry.json signal_logic_version must match versions.json.\n"
        "Run: python scripts/refresh_rules_registry.py"
    )


def test_rules_registry_has_no_empty_hashes() -> None:
    reg = _load_json(REGISTRY)
    rules = reg.get("rules") or []
    for r in rules:
        h = r.get("semantic_hash")
        assert isinstance(h, str) and h.strip(), f"Empty semantic_hash for rule {r.get('rule_id')}"


def test_rules_registry_has_all_js_ts_rules() -> None:
    """Verify the registry contains all 5 JS/TS security rules."""
    reg = _load_json(REGISTRY)
    rule_ids = {r["rule_id"] for r in reg.get("rules", [])}
    expected = {
        "SEC_EVAL_JS_001",
        "SEC_NEW_FUNCTION_JS_001",
        "EXC_EMPTY_CATCH_JS_001",
        "GST_GLOBAL_THIS_MUTATION_001",
        "SEC_DYNAMIC_MODULE_LOAD_JS_001",
    }
    assert expected.issubset(rule_ids), f"Missing rules: {expected - rule_ids}"
