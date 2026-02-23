from __future__ import annotations

from code_audit.web_api.openapi_normalize import schema_signature


def test_schema_signature_sorts_enum_and_required_and_properties() -> None:
    schema = {
        "type": "object",
        "required": ["b", "a"],
        "properties": {
            "z": {"type": "string", "enum": ["b", "a"]},
            "a": {"type": "integer", "minimum": 1},
        },
        "description": "ignored",
        "example": {"a": 1},
    }

    sig = schema_signature(schema, components_schemas={}).sig
    assert sig["type"] == "object"
    assert sig["required"] == ["a", "b"]
    assert list(sig["properties"].keys()) == ["a", "z"]
    assert sig["properties"]["z"]["enum"] == ["a", "b"]
    assert "description" not in sig
    assert "example" not in sig


def test_schema_signature_resolves_ref_and_is_cycle_safe() -> None:
    components = {
        "Node": {
            "type": "object",
            "properties": {
                "next": {"$ref": "#/components/schemas/Node"}
            },
        }
    }

    root = {"$ref": "#/components/schemas/Node"}
    sig = schema_signature(root, components_schemas=components).sig
    assert sig["$ref_resolved"] == "Node"
    # cycle should be represented at the recursive point
    assert sig["target"]["properties"]["next"]["$ref_cycle"] == "Node"


def test_schema_signature_external_ref_is_marked_unknown() -> None:
    sig = schema_signature({"$ref": "https://example.com/schema.json"}, components_schemas={}).sig
    assert sig["ref_kind"] == "external_or_unsupported"
