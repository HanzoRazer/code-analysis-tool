#!/usr/bin/env python3
"""Release gate: enforce semver rules against CHANGELOG breaking declarations.

Rules:
  1. Breaking: yes  →  MAJOR version bump required (vs previous tag)
  2. Breaking: no   →  MAJOR version bump forbidden (vs previous tag)
  3. Breaking: yes  →  at least one contract axis must also be 'yes'
     (Schema, Signals, Rule registry, Exit codes, Confidence, Web API)

First release (no previous tag found) skips rules 1 & 2 (major-bump check).

Usage:
  python scripts/check_semver_breaking_gate.py --tag v1.0.0
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Contract axes that must declare movement when Breaking: yes
CONTRACT_AXES: dict[str, set[str]] = {
    "schema": {"schema", "schemas"},
    "signals": {"signals", "signal"},
    "rule registry": {"rule registry", "rule_registry", "rules", "rule-registry"},
    "exit codes": {"exit codes", "exit_codes", "exit-codes", "exitcodes"},
    "confidence": {"confidence"},
    "web api": {"web api", "web_api", "web-api", "webapi", "api"},
}

# ── Regex helpers ─────────────────────────────────────────────────────────
_HEADER_RE = re.compile(
    r"^##\s+\[?v?(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\]?"
    r"(?:\s*-\s*\d{4}-\d{2}-\d{2})?\s*$",
)
_FIELD_RE = re.compile(
    r"^\s*(?:[-*]\s+)?(?P<key>[A-Za-z][A-Za-z _\-]+?)\s*:\s*(?P<value>\S+)\s*$"
)
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def _strip_v(tag: str) -> str:
    return tag[1:] if tag.startswith("v") else tag


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    m = _SEMVER_RE.match(version)
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _extract_section(lines: list[str], version: str) -> list[str] | None:
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
                break
        elif stripped.startswith("# ") and in_section:
            break
        if in_section:
            section.append(line)
    return section if in_section else None


def _parse_fields(section: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in section:
        m = _FIELD_RE.match(line)
        if m:
            found[m.group("key").strip().lower()] = m.group("value").strip().lower()
    return found


def _resolve_field(raw: dict[str, str], aliases: set[str]) -> str | None:
    for alias in aliases:
        if alias in raw:
            return raw[alias]
    return None


def _find_previous_tag(current_tag: str) -> str | None:
    """Find the most recent semver tag before ``current_tag`` using git."""
    try:
        result = subprocess.run(
            ["git", "tag", "--list", "v*", "--sort=-v:refname"],
            capture_output=True,
            text=True,
            check=True,
            cwd=ROOT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

    current_version = _strip_v(current_tag)
    for line in result.stdout.splitlines():
        tag = line.strip()
        if not tag:
            continue
        v = _strip_v(tag)
        if v == current_version:
            continue
        if _parse_semver(v) is not None:
            return tag
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Semver breaking gate")
    ap.add_argument("--tag", required=True, help="Git tag, e.g. v1.0.0")
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

    current_semver = _parse_semver(version)
    if current_semver is None:
        print(f"ERROR: Tag '{args.tag}' is not a valid semver tag.", file=sys.stderr)
        return 1

    section = _extract_section(lines, version)
    if section is None:
        print(
            f"ERROR: No CHANGELOG section found for version {version}.",
            file=sys.stderr,
        )
        return 1

    raw_fields = _parse_fields(section)

    # ── Extract the Breaking flag ──
    breaking_value = None
    for alias in ("breaking",):
        if alias in raw_fields:
            breaking_value = raw_fields[alias]
            break

    if breaking_value is None:
        print(
            f"ERROR: CHANGELOG section for {version} is missing 'Breaking: yes|no'.",
            file=sys.stderr,
        )
        return 1

    if breaking_value not in ("yes", "no"):
        print(
            f"ERROR: Invalid Breaking value '{breaking_value}'. Must be 'yes' or 'no'.",
            file=sys.stderr,
        )
        return 1

    is_breaking = breaking_value == "yes"

    # ── Rule 3: Breaking:yes implies at least one contract axis is 'yes' ──
    if is_breaking:
        axis_values: dict[str, str | None] = {}
        for canonical, aliases in CONTRACT_AXES.items():
            axis_values[canonical] = _resolve_field(raw_fields, aliases)

        any_axis_yes = any(v == "yes" for v in axis_values.values() if v is not None)
        if not any_axis_yes:
            print(
                f"ERROR: Breaking: yes but no contract axis declares a change.",
                file=sys.stderr,
            )
            print("", file=sys.stderr)
            print(
                "When Breaking is 'yes', at least one of these axes must also be 'yes':",
                file=sys.stderr,
            )
            for canonical in CONTRACT_AXES:
                v = axis_values.get(canonical, "?")
                print(f"  {canonical}: {v}", file=sys.stderr)
            print("", file=sys.stderr)
            print(
                "If no contract axis changed, set Breaking: no instead.",
                file=sys.stderr,
            )
            return 1

    # ── Rules 1 & 2: Breaking ↔ major-bump check ──
    prev_tag = _find_previous_tag(args.tag)

    if prev_tag is None:
        # First release — skip major-bump enforcement
        print(
            f"OK: First release ({version}), Breaking: {breaking_value}. "
            "Major-bump rule skipped (no previous tag)."
        )
        return 0

    prev_semver = _parse_semver(_strip_v(prev_tag))
    if prev_semver is None:
        print(
            f"WARNING: Previous tag '{prev_tag}' is not valid semver. Skipping major-bump check.",
            file=sys.stderr,
        )
        # Don't fail — just warn
        print(f"OK: Breaking: {breaking_value}, previous tag unparseable.")
        return 0

    is_major_bump = current_semver[0] > prev_semver[0]

    # Rule 1: Breaking:yes → MAJOR bump required
    if is_breaking and not is_major_bump:
        print(
            f"ERROR: Breaking: yes but this is NOT a major version bump.",
            file=sys.stderr,
        )
        print(
            f"  Previous: {prev_tag} ({prev_semver[0]}.{prev_semver[1]}.{prev_semver[2]})",
            file=sys.stderr,
        )
        print(
            f"  Current:  v{version} ({current_semver[0]}.{current_semver[1]}.{current_semver[2]})",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        print("Fix: bump the major version (e.g. v2.0.0) or set Breaking: no.", file=sys.stderr)
        return 1

    # Rule 2: Breaking:no → MAJOR bump forbidden
    if not is_breaking and is_major_bump:
        print(
            f"ERROR: Major version bump but Breaking: no.",
            file=sys.stderr,
        )
        print(
            f"  Previous: {prev_tag} ({prev_semver[0]}.{prev_semver[1]}.{prev_semver[2]})",
            file=sys.stderr,
        )
        print(
            f"  Current:  v{version} ({current_semver[0]}.{current_semver[1]}.{current_semver[2]})",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        print(
            "Fix: set Breaking: yes (and declare which contract axes changed), "
            "or use a minor/patch bump instead.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: Semver check passed. Breaking: {breaking_value}, "
        f"previous: {prev_tag} → current: v{version}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
