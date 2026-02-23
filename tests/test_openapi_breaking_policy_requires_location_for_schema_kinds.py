from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "tests" / "contracts" / "openapi_breaking_policy.json"


def _is_schema_kind(kind: str) -> bool:
    # Tight, future-proof heuristic: any kind that mentions schema must be precisely located.
    return "_schema_" in kind


def _check(items: list[dict], *, section: str) -> None:
    bad = []
    for it in items:
        kind = it.get("kind")
        if not isinstance(kind, str) or not kind:
            continue
        if not _is_schema_kind(kind):
            continue
        loc = it.get("location")
        if not isinstance(loc, str) or not loc.strip():
            # Display anchor (op/path) for diagnosis
            anchor = it.get("op") or it.get("path") or "<missing op/path>"
            bad.append((kind, str(anchor)))

    if bad:
        lines = [
            "OpenAPI breaking policy invalid: schema-related policy items must include a non-empty 'location'.",
            f"Section: {section}",
            "",
            "Missing location for:",
        ]
        for kind, anchor in bad:
            lines.append(f"- kind={kind} anchor={anchor}")
        lines.append("")
        lines.append(
            "Fix: add 'location' to each schema-related allowlist entry, e.g. "
            "'responses.200.content.application/json.schema' or 'requestBody.content.application/json.schema'."
        )
        raise AssertionError("\n".join(lines))


def test_policy_requires_location_for_schema_kinds_allow_unknown() -> None:
    assert POLICY_PATH.exists(), "Missing tests/contracts/openapi_breaking_policy.json"
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    items = policy.get("allow_unknown") or []
    assert isinstance(items, list)
    for it in items:
        assert isinstance(it, dict)
    _check(items, section="allow_unknown")


def test_policy_requires_location_for_schema_kinds_allow_breaking() -> None:
    assert POLICY_PATH.exists(), "Missing tests/contracts/openapi_breaking_policy.json"
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    items = policy.get("allow_breaking") or []
    assert isinstance(items, list)
    for it in items:
        assert isinstance(it, dict)
    _check(items, section="allow_breaking")
