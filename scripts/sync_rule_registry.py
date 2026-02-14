#!/usr/bin/env python3
"""Regenerate docs/rule_registry.json from canonical rules.py.

Usage:
    python scripts/sync_rule_registry.py          # check mode (CI)
    python scripts/sync_rule_registry.py --write  # write mode (dev)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_PY = ROOT / "src" / "code_audit" / "rules.py"
OUTPUT = ROOT / "docs" / "rule_registry.json"


def load_all_rule_ids() -> list[str]:
    """Load ALL_RULE_IDS from rules.py without importing the full package."""
    # Execute rules.py in isolation to avoid triggering __init__.py imports
    namespace: dict = {}
    exec(RULES_PY.read_text(encoding="utf-8"), namespace)
    return namespace["ALL_RULE_IDS"]


def generate() -> str:
    """Generate rule_registry.json content from ALL_RULE_IDS."""
    data = {"supported_rule_ids": load_all_rule_ids()}
    return json.dumps(data, indent=2) + "\n"


def main() -> int:
    write_mode = "--write" in sys.argv

    expected = generate()

    if write_mode:
        OUTPUT.write_text(expected, encoding="utf-8")
        print(f"Wrote {OUTPUT}")
        return 0

    # Check mode
    if not OUTPUT.exists():
        print(f"FAIL: {OUTPUT} does not exist", file=sys.stderr)
        print("Fix: python scripts/sync_rule_registry.py --write", file=sys.stderr)
        return 1

    actual = OUTPUT.read_text(encoding="utf-8")

    if actual != expected:
        print(f"FAIL: {OUTPUT} is out of sync with rules.py", file=sys.stderr)
        print("Fix: python scripts/sync_rule_registry.py --write", file=sys.stderr)
        return 1

    print(f"OK: {OUTPUT} matches rules.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
