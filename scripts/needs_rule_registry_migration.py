#!/usr/bin/env python3
"""Detect whether rule registry migration is required.

Migration is required when:
  - PUBLIC_RULE_IDS is empty in src/code_audit/rules.py
  - docs/rule_registry.json contains supported_rule_ids

Exit codes:
  0 -> no migration required
  1 -> migration required

Usage:
    python scripts/needs_rule_registry_migration.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PY = ROOT / "src" / "code_audit" / "rules.py"
DOCS_JSON = ROOT / "docs" / "rule_registry.json"


def _extract_public_ids(text: str) -> list[str]:
    """Extract rule IDs inside PUBLIC_RULE_IDS sorted([...]).

    Conservative parse — only used for migration detection.
    Handles both quoted strings ("SEC_EVAL_001") and variable
    references (SEC_EVAL_001) since rules.py may use either style.
    """
    m = re.search(
        r'PUBLIC_RULE_IDS:\s*list\[str\]\s*=\s*sorted\(\[\s*(.*?)\n\]\)',
        text,
        re.S,
    )
    if not m:
        return []
    block = m.group(1)
    # Try quoted strings first
    quoted = re.findall(r'"([^"]+)"', block)
    if quoted:
        return quoted
    # Fall back to variable references (uppercase identifiers on their own lines)
    refs = re.findall(r'\b([A-Z][A-Z0-9_]+)\b', block)
    return refs


def main() -> int:
    if not RULES_PY.exists():
        print(f"rules.py not found: {RULES_PY}")
        return 0

    rules_text = RULES_PY.read_text(encoding="utf-8")
    public_ids = _extract_public_ids(rules_text)

    if not DOCS_JSON.exists():
        print("No docs/rule_registry.json found. No migration required.")
        return 0

    try:
        docs_obj = json.loads(DOCS_JSON.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"Invalid docs/rule_registry.json: {e}")
        return 0

    docs_ids = docs_obj.get("supported_rule_ids") or []

    if len(public_ids) == 0 and len(docs_ids) > 0:
        print("Migration required:")
        print("  PUBLIC_RULE_IDS is empty")
        print("  docs/rule_registry.json contains supported_rule_ids")
        print("")
        print("Run locally:")
        print("  python scripts/migrate_rule_ids_to_public.py --write")
        print("  python scripts/sync_rule_registry.py --write")
        return 1

    print("No rule registry migration required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
