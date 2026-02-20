#!/usr/bin/env python3
"""Release gate: enforce structured CHANGELOG template with contract-axis declarations.

Each release section must contain a template block declaring the state of
every governed contract axis:

    Schema: yes|no
    Signals: yes|no
    Rule registry: yes|no
    Exit codes: yes|no
    Confidence: yes|no
    Web API: yes|no
    Breaking: yes|no

Usage:
  python scripts/check_changelog_template.py --tag v1.0.0
  python scripts/check_changelog_template.py --tag v1.0.0 --require-bullets
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# ── Required fields and their recognized aliases ──────────────────────────
REQUIRED_FIELDS: dict[str, set[str]] = {
    "schema": {"schema", "schemas"},
    "signals": {"signals", "signal"},
    "rule registry": {"rule registry", "rule_registry", "rules", "rule-registry"},
    "exit codes": {"exit codes", "exit_codes", "exit-codes", "exitcodes"},
    "confidence": {"confidence"},
    "web api": {"web api", "web_api", "web-api", "webapi", "api"},
    "breaking": {"breaking"},
}

ALLOWED_VALUES = {"yes", "no"}

# ── Header regex (matches ## [X.Y.Z] / ## X.Y.Z with optional date) ──────
_HEADER_RE = re.compile(
    r"^##\s+\[?v?(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\]?"
    r"(?:\s*-\s*(?P<date>\d{4}-\d{2}-\d{2}))?\s*$",
)

# Match field lines like  "Schema: yes" or "- Schema: no" or "* Schema: yes"
_FIELD_RE = re.compile(
    r"^\s*(?:[-*]\s+)?(?P<key>[A-Za-z][A-Za-z _\-]+?)\s*:\s*(?P<value>\S+)\s*$"
)


def _strip_v(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def _extract_section(lines: list[str], version: str) -> list[str] | None:
    """Extract all lines belonging to the section for ``version``."""
    in_section = False
    section: list[str] = []
    for line in lines:
        stripped = line.strip()
        m = _HEADER_RE.match(stripped)
        if m:
            if m.group("version") == version:
                in_section = True
                continue
            elif in_section:
                break  # hit next version header
        elif stripped.startswith("# ") and in_section:
            break  # hit a top-level heading
        if in_section:
            section.append(line)
    return section if in_section else None


def _parse_fields(section: list[str]) -> dict[str, str]:
    """Parse ``Key: value`` lines from a section."""
    found: dict[str, str] = {}
    for line in section:
        m = _FIELD_RE.match(line)
        if m:
            key = m.group("key").strip().lower()
            val = m.group("value").strip().lower()
            found[key] = val
    return found


def _resolve_field(raw_fields: dict[str, str], canonical: str, aliases: set[str]) -> str | None:
    """Return the value for a field given its aliases, or None if absent."""
    for alias in aliases:
        if alias in raw_fields:
            return raw_fields[alias]
    return None


def _has_bullet_list(section: list[str]) -> bool:
    """Check if the section contains at least one markdown bullet point."""
    for line in section:
        stripped = line.strip()
        if stripped.startswith("- ") or stripped.startswith("* "):
            return True
    return False


def _example_block() -> str:
    return (
        "    Schema: no\n"
        "    Signals: no\n"
        "    Rule registry: no\n"
        "    Exit codes: no\n"
        "    Confidence: no\n"
        "    Web API: no\n"
        "    Breaking: no\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Check CHANGELOG template enforcement")
    ap.add_argument("--tag", required=True, help="Git tag, e.g. v1.0.0")
    ap.add_argument(
        "--require-bullets",
        action="store_true",
        help="Require at least one bullet point in the section",
    )
    ap.add_argument(
        "--changelog",
        default=str(ROOT / "CHANGELOG.md"),
        help="Path to CHANGELOG.md",
    )
    args = ap.parse_args()

    changelog = Path(args.changelog)
    if not changelog.exists():
        print(f"ERROR: CHANGELOG.md not found at {changelog}", file=sys.stderr)
        return 1

    lines = changelog.read_text(encoding="utf-8").splitlines()
    version = _strip_v(args.tag)

    section = _extract_section(lines, version)
    if section is None:
        print(
            f"ERROR: No section found for version {version} in CHANGELOG.md.",
            file=sys.stderr,
        )
        return 1

    raw_fields = _parse_fields(section)
    errors: list[str] = []

    for canonical, aliases in REQUIRED_FIELDS.items():
        value = _resolve_field(raw_fields, canonical, aliases)
        if value is None:
            errors.append(f"  Missing required field: {canonical}")
        elif value not in ALLOWED_VALUES:
            errors.append(
                f"  Invalid value for '{canonical}': '{value}' (must be 'yes' or 'no')"
            )

    if args.require_bullets and not _has_bullet_list(section):
        errors.append("  Section must contain at least one bullet point (- or *)")

    if errors:
        print(
            f"ERROR: CHANGELOG template validation failed for version {version}:",
            file=sys.stderr,
        )
        for e in errors:
            print(e, file=sys.stderr)
        print("", file=sys.stderr)
        print("Each release section must include these fields:", file=sys.stderr)
        print("", file=sys.stderr)
        print(_example_block(), file=sys.stderr)
        return 1

    found_summary = ", ".join(
        f"{c}={_resolve_field(raw_fields, c, a)}" for c, a in REQUIRED_FIELDS.items()
    )
    print(f"OK: CHANGELOG template valid for {version}: {found_summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
