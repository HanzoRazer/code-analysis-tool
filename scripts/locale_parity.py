#!/usr/bin/env python3
"""Locale parity checker — ensures all locales share identical keys with en/.

Usage:
    python scripts/locale_parity.py i18n/
    python scripts/locale_parity.py i18n/ --format json

Exit codes:
    0  All locales match en/ (or only en/ exists)
    1  Key divergence detected
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def extract_keys(obj: object, prefix: str = "") -> set[str]:
    """Recursively extract all leaf key paths from a nested dict."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{prefix}.{k}" if prefix else k
            child_keys = extract_keys(v, full)
            keys.update(child_keys if child_keys else {full})
    elif isinstance(obj, list):
        # Lists are leaf values — don't recurse into array items
        keys.add(prefix)
    else:
        keys.add(prefix)
    return keys


def load_locale_keys(locale_dir: Path) -> dict[str, set[str]]:
    """Load all .json files in a locale dir and return {filename: key_set}."""
    result: dict[str, set[str]] = {}
    for f in sorted(locale_dir.glob("*.json")):
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        result[f.name] = extract_keys(data)
    return result


def check_parity(i18n_root: Path) -> list[dict]:
    """Compare every non-en locale against en/. Return list of errors."""
    en_dir = i18n_root / "en"
    if not en_dir.is_dir():
        return [{"error": "Missing canonical locale: i18n/en/"}]

    en_keys = load_locale_keys(en_dir)
    en_files = set(en_keys.keys())
    errors: list[dict] = []

    locale_dirs = sorted(
        d for d in i18n_root.iterdir()
        if d.is_dir() and d.name != "en" and not d.name.startswith(".")
    )

    if not locale_dirs:
        return []  # Only en/ exists — nothing to compare

    for locale_dir in locale_dirs:
        locale = locale_dir.name
        locale_keys = load_locale_keys(locale_dir)
        locale_files = set(locale_keys.keys())

        # Check for missing or extra files
        missing_files = en_files - locale_files
        extra_files = locale_files - en_files

        for f in sorted(missing_files):
            errors.append({
                "locale": locale,
                "file": f,
                "type": "missing_file",
                "detail": f"{locale}/{f} does not exist (required by en/)",
            })

        for f in sorted(extra_files):
            errors.append({
                "locale": locale,
                "file": f,
                "type": "extra_file",
                "detail": f"{locale}/{f} has no en/ counterpart",
            })

        # Check key parity for files that exist in both
        for f in sorted(en_files & locale_files):
            missing_keys = en_keys[f] - locale_keys[f]
            extra_keys = locale_keys[f] - en_keys[f]

            for k in sorted(missing_keys):
                errors.append({
                    "locale": locale,
                    "file": f,
                    "type": "missing_key",
                    "detail": f"{locale}/{f} is missing key: {k}",
                })

            for k in sorted(extra_keys):
                errors.append({
                    "locale": locale,
                    "file": f,
                    "type": "extra_key",
                    "detail": f"{locale}/{f} has extra key: {k}",
                })

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check that all i18n locales have identical keys to en/."
    )
    parser.add_argument(
        "i18n_root",
        type=Path,
        help="Path to the i18n/ directory",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    if not args.i18n_root.is_dir():
        print(f"Error: {args.i18n_root} is not a directory", file=sys.stderr)
        sys.exit(1)

    errors = check_parity(args.i18n_root)

    if args.format == "json":
        json.dump({"errors": errors, "count": len(errors)}, sys.stdout, indent=2)
        print()
    else:
        if not errors:
            print("✓ All locales match en/ (0 errors)")
        else:
            print(f"✗ {len(errors)} parity error(s)\n")
            for e in errors:
                print(f"  [{e['type']}] {e['detail']}")

    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
