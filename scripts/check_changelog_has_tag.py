#!/usr/bin/env python3
"""Release gate: verify that CHANGELOG.md contains an entry for a given tag.

Accepts common Keep a Changelog header formats:
  ## [X.Y.Z]             (with brackets, no date)
  ## [X.Y.Z] - YYYY-MM-DD (with brackets and date)
  ## X.Y.Z               (no brackets, no date)
  ## X.Y.Z - YYYY-MM-DD  (no brackets, with date)
  ## [vX.Y.Z]            (v-prefix)

Usage:
  python scripts/check_changelog_has_tag.py --tag v1.0.0
  python scripts/check_changelog_has_tag.py --tag v1.0.0 --require-date
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Match  ## [X.Y.Z]  or  ## X.Y.Z  with optional v-prefix and optional date
_HEADER_RE = re.compile(
    r"^##\s+\[?v?(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\]?"
    r"(?:\s*-\s*(?P<date>\d{4}-\d{2}-\d{2}))?\s*$",
)


def _strip_v(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def find_entry(lines: list[str], version: str) -> tuple[int | None, str | None]:
    """Return (line_number, date_string_or_None) for the first matching header."""
    for i, line in enumerate(lines):
        m = _HEADER_RE.match(line.strip())
        if m and m.group("version") == version:
            return i, m.group("date")
    return None, None


def main() -> int:
    ap = argparse.ArgumentParser(description="Check CHANGELOG entry for a release tag")
    ap.add_argument("--tag", required=True, help="Git tag, e.g. v1.0.0")
    ap.add_argument(
        "--require-date",
        action="store_true",
        help="Require the header to include a YYYY-MM-DD date",
    )
    ap.add_argument(
        "--changelog",
        default=str(ROOT / "CHANGELOG.md"),
        help="Path to CHANGELOG.md (default: repo root)",
    )
    args = ap.parse_args()

    changelog = Path(args.changelog)
    if not changelog.exists():
        print(f"ERROR: CHANGELOG.md not found at {changelog}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Fix: create a CHANGELOG.md with an entry for your release:", file=sys.stderr)
        print(f"  ## [{args.tag.lstrip('v')}] - YYYY-MM-DD", file=sys.stderr)
        return 1

    lines = changelog.read_text(encoding="utf-8").splitlines()
    version = _strip_v(args.tag)
    line_no, date = find_entry(lines, version)

    if line_no is None:
        print(
            f"ERROR: No CHANGELOG.md entry found for version {version}.",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        print("Searched for headers matching any of:", file=sys.stderr)
        print(f"  ## [{version}] - YYYY-MM-DD", file=sys.stderr)
        print(f"  ## [{version}]", file=sys.stderr)
        print(f"  ## {version} - YYYY-MM-DD", file=sys.stderr)
        print(f"  ## {version}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Fix: add a section to CHANGELOG.md:", file=sys.stderr)
        print(f"  ## [{version}] - YYYY-MM-DD", file=sys.stderr)
        return 1

    if args.require_date and not date:
        print(
            f"ERROR: CHANGELOG entry for {version} (line {line_no + 1}) is missing "
            "a release date (YYYY-MM-DD).",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        print("Fix: update the header to include a date:", file=sys.stderr)
        print(f"  ## [{version}] - YYYY-MM-DD", file=sys.stderr)
        return 1

    date_str = f" (date: {date})" if date else " (no date)"
    print(f"OK: CHANGELOG entry found for {version} at line {line_no + 1}{date_str}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
