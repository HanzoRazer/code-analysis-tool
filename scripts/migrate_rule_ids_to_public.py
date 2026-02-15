#!/usr/bin/env python3
"""One-time migration: copy docs/rule_registry.json supported_rule_ids into
PUBLIC_RULE_IDS in src/code_audit/rules.py.

Usage:
    python scripts/migrate_rule_ids_to_public.py          # dry-run (default)
    python scripts/migrate_rule_ids_to_public.py --write   # mutate rules.py
    python scripts/migrate_rule_ids_to_public.py --force   # overwrite non-empty

Guarantees:
    - Deterministic: sorted(set(...))
    - Validates rule ID format via regex
    - Refuses to overwrite non-empty PUBLIC_RULE_IDS unless --force
    - Dry-run by default; --write required to mutate
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_SOURCE = ROOT / "docs" / "rule_registry.json"
DEFAULT_RULES_PY = ROOT / "src" / "code_audit" / "rules.py"

RULE_ID_RE = re.compile(r"^[A-Z]{2,4}_[A-Z][A-Z0-9_]*_[0-9]{3}$")


def _load_ids(source: Path) -> list[str]:
    """Load rule IDs from docs/rule_registry.json."""
    if not source.exists():
        raise FileNotFoundError(f"Missing source registry: {source}")
    obj = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("rule_registry.json must be a JSON object")
    ids = obj.get("supported_rule_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        raise ValueError(
            "rule_registry.json must contain supported_rule_ids: list[str]"
        )
    return ids


def _normalize_ids(ids: list[str]) -> list[str]:
    """Sort, deduplicate, and validate rule IDs."""
    ids2 = sorted(set(ids))
    bad = [x for x in ids2 if not RULE_ID_RE.match(x)]
    if bad:
        raise ValueError(
            f"Invalid rule id(s): {bad[:10]}{'...' if len(bad) > 10 else ''}"
        )
    return ids2


def _find_public_block(text: str) -> tuple[int, int]:
    """Find the slice covering the list contents inside:

        PUBLIC_RULE_IDS: list[str] = sorted([
            <CONTENTS>
        ])

    Returns (start_index, end_index) for <CONTENTS>.
    """
    anchor = "PUBLIC_RULE_IDS: list[str] = sorted(["
    i = text.find(anchor)
    if i < 0:
        raise ValueError("Could not find PUBLIC_RULE_IDS anchor in rules.py")

    # Find the opening bracket '[' and then the matching close '])' line.
    open_i = text.find("[", i)
    if open_i < 0:
        raise ValueError("Could not find '[' after PUBLIC_RULE_IDS anchor")

    # Close at the first occurrence of "\n])" after open_i.
    close_marker = "\n])"
    close_i = text.find(close_marker, open_i)
    if close_i < 0:
        raise ValueError(
            "Could not find closing '\\n])' for PUBLIC_RULE_IDS block"
        )

    start = open_i + 1  # after '['
    end = close_i  # start of "\n])"
    return start, end


def _current_public_ids(text: str, start: int, end: int) -> list[str]:
    """Extract rule IDs from the PUBLIC_RULE_IDS block.

    Handles both quoted strings ("SEC_EVAL_001") and variable
    references (SEC_EVAL_001) since rules.py may use either style.
    """
    block = text[start:end].strip()
    if not block:
        return []
    # Try quoted strings first
    quoted = re.findall(r'"([^"]+)"', block)
    if quoted:
        return quoted
    # Fall back to variable references (uppercase identifiers)
    refs = re.findall(r'\b([A-Z][A-Z0-9_]+)\b', block)
    return refs


def _render_ids(ids: list[str], indent: str = "    ") -> str:
    """Render IDs as one-per-line string literals with trailing commas."""
    if not ids:
        return ""
    return "\n".join(f'{indent}"{rid}",' for rid in ids) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=(
            "One-time migration: copy docs/rule_registry.json "
            "supported_rule_ids into PUBLIC_RULE_IDS in "
            "src/code_audit/rules.py"
        ),
    )
    ap.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="Path to existing docs/rule_registry.json",
    )
    ap.add_argument(
        "--rules-py",
        type=Path,
        default=DEFAULT_RULES_PY,
        help="Path to src/code_audit/rules.py",
    )
    ap.add_argument(
        "--write",
        action="store_true",
        help="Write changes to rules.py (default is dry-run)",
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="Overwrite PUBLIC_RULE_IDS even if it is non-empty",
    )
    args = ap.parse_args()

    try:
        ids = _normalize_ids(_load_ids(args.source))
    except Exception as e:
        print(
            f"error: failed to load/validate source ids: {e}", file=sys.stderr
        )
        return 2

    if not args.rules_py.exists():
        print(f"error: rules.py not found: {args.rules_py}", file=sys.stderr)
        return 2

    text = args.rules_py.read_text(encoding="utf-8")
    try:
        start, end = _find_public_block(text)
    except Exception as e:
        print(
            f"error: failed to locate PUBLIC_RULE_IDS block: {e}",
            file=sys.stderr,
        )
        return 2

    existing = _current_public_ids(text, start, end)
    if existing and not args.force:
        print(
            "error: PUBLIC_RULE_IDS is already non-empty. Refusing to "
            "overwrite.\n"
            "  Use --force to overwrite.\n"
            f"  Existing count={len(existing)}",
            file=sys.stderr,
        )
        return 2

    # Preserve indentation used in file: assume 4 spaces inside list.
    replacement = _render_ids(ids, indent="    ")
    new_text = text[:start] + "\n" + replacement + text[end:]

    if not args.write:
        print(
            f"Dry run OK.\n"
            f"  source: {args.source}\n"
            f"  target: {args.rules_py}"
        )
        print(f"  would write PUBLIC_RULE_IDS count={len(ids)}")
        return 0

    args.rules_py.write_text(new_text, encoding="utf-8")
    print(f"Wrote PUBLIC_RULE_IDS count={len(ids)} to {args.rules_py}")
    print("Next: python scripts/sync_rule_registry.py --write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
