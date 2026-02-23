from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "tests" / "contracts" / "openapi_breaking_policy.json"


def _item_key(it: dict) -> tuple:
    kind = it.get("kind")
    op = it.get("op")
    path = it.get("path")
    loc = it.get("location") or ""

    # Schema guarantees kind + (op or path). We enforce deterministic keying here.
    if op is not None:
        return ("op", str(kind), str(op), str(loc))
    return ("path", str(kind), str(path), str(loc))


def _is_sorted_unique(items: list[dict]) -> tuple[bool, list[tuple], list[tuple]]:
    keys = [_item_key(it) for it in items]
    sorted_keys = sorted(keys)
    duplicates = []
    seen: set[tuple] = set()
    for k in keys:
        if k in seen:
            duplicates.append(k)
        else:
            seen.add(k)
    return keys == sorted_keys, duplicates, keys


def _format_key(k: tuple) -> str:
    # ("op"|"path", kind, op_or_path, location)
    mode, kind, target, loc = k
    loc_s = f" @ {loc}" if loc else ""
    return f"{mode}:{kind}:{target}{loc_s}"


def test_openapi_breaking_policy_allow_unknown_sorted_unique_and_no_duplicate_match_keys() -> None:
    assert POLICY_PATH.exists(), "Missing tests/contracts/openapi_breaking_policy.json"
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    items = policy.get("allow_unknown") or []
    assert isinstance(items, list)
    for it in items:
        assert isinstance(it, dict)
        has_op = "op" in it and it["op"] is not None
        has_path = "path" in it and it["path"] is not None
        if has_op and has_path:
            raise AssertionError(
                "OpenAPI breaking policy invalid: item sets both 'op' and 'path'. "
                "Choose exactly one to avoid ambiguity."
            )

    is_sorted, dups, keys = _is_sorted_unique(items)
    if dups:
        lines = [
            "OpenAPI breaking policy invalid: allow_unknown contains duplicate match keys.",
            "Duplicates:",
        ]
        lines.extend([f"- {_format_key(k)}" for k in sorted(set(dups))])
        raise AssertionError("\n".join(lines))

    if not is_sorted:
        lines = [
            "OpenAPI breaking policy invalid: allow_unknown is not sorted by (op|path, kind, target, location).",
            "Expected order:",
        ]
        lines.extend([f"- {_format_key(k)}" for k in sorted(keys)])
        lines.append("")
        lines.append("Fix: sort allow_unknown entries deterministically by the key above.")
        raise AssertionError("\n".join(lines))


def test_openapi_breaking_policy_allow_breaking_sorted_unique_and_no_duplicate_match_keys() -> None:
    assert POLICY_PATH.exists(), "Missing tests/contracts/openapi_breaking_policy.json"
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    items = policy.get("allow_breaking") or []
    assert isinstance(items, list)
    for it in items:
        assert isinstance(it, dict)
        has_op = "op" in it and it["op"] is not None
        has_path = "path" in it and it["path"] is not None
        if has_op and has_path:
            raise AssertionError(
                "OpenAPI breaking policy invalid: item sets both 'op' and 'path'. "
                "Choose exactly one to avoid ambiguity."
            )

    is_sorted, dups, keys = _is_sorted_unique(items)
    if dups:
        lines = [
            "OpenAPI breaking policy invalid: allow_breaking contains duplicate match keys.",
            "Duplicates:",
        ]
        lines.extend([f"- {_format_key(k)}" for k in sorted(set(dups))])
        raise AssertionError("\n".join(lines))

    if not is_sorted:
        lines = [
            "OpenAPI breaking policy invalid: allow_breaking is not sorted by (op|path, kind, target, location).",
            "Expected order:",
        ]
        lines.extend([f"- {_format_key(k)}" for k in sorted(keys)])
        lines.append("")
        lines.append("Fix: sort allow_breaking entries deterministically by the key above.")
        raise AssertionError("\n".join(lines))
