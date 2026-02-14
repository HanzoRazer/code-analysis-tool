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

# Add src to path for import
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from code_audit.rules import ALL_RULE_IDS

OUTPUT = ROOT / "docs" / "rule_registry.json"


def generate() -> str:
    """Generate rule_registry.json content from ALL_RULE_IDS."""
    data = {"supported_rule_ids": list(ALL_RULE_IDS)}
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
