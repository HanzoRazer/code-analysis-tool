#!/usr/bin/env python3
"""Release gate: enforce that CHANGELOG axis declarations match actual movement.

For each contract axis declared ``yes`` in the CHANGELOG section for a tag,
this script verifies that real, machine-verifiable movement occurred between
the previous semver tag and the current tag.

Truth rules:
  Schema: yes    => at least one governed schema file changed
  Signals: yes   => signal_logic_version bumped OR signal manifests changed
  Rule registry: yes => rule registry file or manifest changed
  Exit codes: yes    => exit-code policy manifest or source changed
  Confidence: yes    => confidence_logic_version bumped OR confidence files changed
  Web API: yes       => OpenAPI snapshot (docs/openapi.json) or schema changed
  Breaking: yes      => enforced separately by check_semver_breaking_gate.py

The ``--enforce-no`` flag optionally fails when an axis declares ``no`` but
movement is detected.

Usage:
  python scripts/check_changelog_truth.py --tag v1.0.0
  python scripts/check_changelog_truth.py --tag v1.0.0 --enforce-no
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SEMVER_TAG_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


# ── Git helpers ───────────────────────────────────────────────────────────


def _run(cmd: list[str]) -> str:
    r = subprocess.run(cmd, cwd=str(ROOT), check=True, capture_output=True, text=True)
    return r.stdout


def parse_tag(tag: str) -> tuple[int, int, int]:
    m = SEMVER_TAG_RE.match(tag)
    if not m:
        raise ValueError(f"Invalid semver tag: {tag}")
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def semver_tags() -> list[str]:
    tags = [t.strip() for t in _run(["git", "tag", "--list", "v*"]).splitlines() if t.strip()]
    tags = [t for t in tags if SEMVER_TAG_RE.match(t)]
    tags.sort(key=parse_tag)
    return tags


def prev_tag(current: str, tags: list[str]) -> str | None:
    merged = list({*tags, current})
    merged.sort(key=parse_tag)
    idx = merged.index(current)
    return merged[idx - 1] if idx > 0 else None


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git_file_bytes(tag: str, path: str) -> bytes | None:
    """Return bytes of file at ``tag:path``, or ``None`` if absent."""
    try:
        r = subprocess.run(
            ["git", "show", f"{tag}:{path}"],
            cwd=str(ROOT),
            check=True,
            capture_output=True,
        )
        return r.stdout
    except subprocess.CalledProcessError:
        return None


def file_changed_between(prev: str, cur: str, path: str) -> bool:
    a = git_file_bytes(prev, path)
    b = git_file_bytes(cur, path)
    if a is None and b is None:
        return False
    if a is None or b is None:
        return True
    return sha256_bytes(a) != sha256_bytes(b)


def any_changed(prev: str, cur: str, paths: list[str]) -> bool:
    return any(file_changed_between(prev, cur, p) for p in paths)


def _file_exists_in_either(prev: str, cur: str, path: str) -> bool:
    return git_file_bytes(cur, path) is not None or git_file_bytes(prev, path) is not None


def _existing_paths(prev: str, cur: str, paths: list[str]) -> list[str]:
    """Filter to paths that exist in at least one of the two tags."""
    return [p for p in paths if _file_exists_in_either(prev, cur, p)]


# ── CHANGELOG parsing ────────────────────────────────────────────────────


def extract_version_section(text: str, version: str) -> str | None:
    header_res = [
        re.compile(rf"^##\s*\[\s*{re.escape(version)}\s*\].*$"),
        re.compile(rf"^##\s*{re.escape(version)}.*$"),
        re.compile(rf"^##\s*\[\s*v{re.escape(version)}\s*\].*$"),
        re.compile(rf"^##\s*v{re.escape(version)}.*$"),
    ]
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if any(r.match(line) for r in header_res):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("## "):
            end = j
            break
    return "\n".join(lines[start:end])


def extract_axis_values(section: str) -> dict[str, str]:
    """Extract normalised axis values (``yes`` | ``no``)."""
    out: dict[str, str] = {}
    for raw in section.splitlines():
        line = raw.strip()
        m = re.match(
            r"^(?:[-*]\s+)?"
            r"(Schema|Signals|Rule registry|Exit codes|Confidence|Web API|Breaking)"
            r"\s*:\s*(yes|no)\s*$",
            line,
            flags=re.IGNORECASE,
        )
        if not m:
            continue
        k = m.group(1).strip().lower()
        v = m.group(2).strip().lower()
        out[k] = v
    return out


# ── Version-anchor readers ───────────────────────────────────────────────


def _read_const(tag: str, path: str, name: str) -> str | None:
    b = git_file_bytes(tag, path)
    if b is None:
        return None
    txt = b.decode("utf-8", errors="replace")
    m = re.search(rf"\b{name}(?:\s*:\s*\S+)?\s*=\s*\"([^\"]+)\"", txt)
    return m.group(1) if m else None


def read_signal_logic_version(tag: str) -> str | None:
    return _read_const(tag, "src/code_audit/model/run_result.py", "signal_logic_version")


def read_confidence_logic_version(tag: str) -> str | None:
    return _read_const(tag, "src/code_audit/insights/confidence.py", "confidence_logic_version")


# ── Axis check result ────────────────────────────────────────────────────


@dataclass(frozen=True)
class AxisCheck:
    name: str
    declared: str
    moved: bool
    details: str


# ── Main ─────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description="Changelog truth enforcement")
    ap.add_argument("--tag", default=os.environ.get("GITHUB_REF_NAME", ""), help="Current tag vX.Y.Z")
    ap.add_argument("--changelog", default="CHANGELOG.md")
    ap.add_argument(
        "--enforce-no",
        action="store_true",
        help="Also fail if an axis declares 'no' but movement is detected",
    )
    args = ap.parse_args()

    cur_tag = (args.tag or "").strip()
    if not SEMVER_TAG_RE.match(cur_tag):
        print(
            f"ERROR: changelog truth enforcement expects a stable tag vX.Y.Z, got '{cur_tag}'.",
            file=sys.stderr,
        )
        return 1

    tags = semver_tags()
    prev = prev_tag(cur_tag, tags)
    if prev is None:
        print(
            f"OK: no previous semver tag found; skipping changelog truth "
            f"comparisons for first release ({cur_tag})."
        )
        return 0

    version = cur_tag[1:]
    changelog_path = ROOT / args.changelog
    if not changelog_path.exists():
        print(f"ERROR: {args.changelog} not found.", file=sys.stderr)
        return 1

    changelog_text = changelog_path.read_text(encoding="utf-8", errors="replace")
    section = extract_version_section(changelog_text, version)
    if section is None:
        print(
            "ERROR: changelog truth enforcement failed — "
            "missing version section in CHANGELOG.",
            file=sys.stderr,
        )
        print(f"  Tag: {cur_tag}", file=sys.stderr)
        return 1

    axes = extract_axis_values(section)
    required_keys = [
        "schema", "signals", "rule registry", "exit codes",
        "confidence", "web api", "breaking",
    ]
    missing = [k for k in required_keys if k not in axes]
    if missing:
        print(
            "ERROR: changelog truth enforcement failed — "
            "missing required axis declarations.",
            file=sys.stderr,
        )
        print(f"  Tag: {cur_tag}", file=sys.stderr)
        for k in missing:
            print(f"  Missing: {k.title()}: yes|no", file=sys.stderr)
        return 1

    checks: list[AxisCheck] = []

    # ── Schema movement ──────────────────────────────────────────────
    schema_paths = _existing_paths(prev, cur_tag, [
        "schemas/run_result.schema.json",
        "schemas/debt_snapshot.schema.json",
        "schemas/signals_latest.schema.json",
        "schemas/user_event.schema.json",
        "schemas/drift_budget_signal.schema.json",
        "schemas/rule_registry.schema.json",
    ])
    schema_moved = any_changed(prev, cur_tag, schema_paths)
    checks.append(AxisCheck(
        name="schema",
        declared=axes["schema"],
        moved=schema_moved,
        details=f"schema files changed between {prev}..{cur_tag}: {schema_moved}",
    ))

    # ── Signals movement ─────────────────────────────────────────────
    prev_sig = read_signal_logic_version(prev)
    cur_sig = read_signal_logic_version(cur_tag)
    sig_bumped = prev_sig is not None and cur_sig is not None and prev_sig != cur_sig
    signal_manifest_paths = _existing_paths(prev, cur_tag, [
        "tests/contracts/translator_policy_manifest.json",
        "tests/contracts/golden_fixtures_manifest.json",
        "tests/contracts/logic_manifest.json",
    ])
    signal_manifests_moved = any_changed(prev, cur_tag, signal_manifest_paths)
    signals_moved = sig_bumped or signal_manifests_moved
    checks.append(AxisCheck(
        name="signals",
        declared=axes["signals"],
        moved=signals_moved,
        details=(
            f"signal_logic_version bumped: {sig_bumped} "
            f"(prev={prev_sig}, cur={cur_sig}); "
            f"manifests changed: {signal_manifests_moved}"
        ),
    ))

    # ── Rule registry movement ───────────────────────────────────────
    rr_paths = _existing_paths(prev, cur_tag, [
        "docs/rule_registry.json",
        "tests/contracts/public_rule_registry_manifest.json",
        "tests/contracts/rule_registry_manifest.json",
    ])
    rr_moved = any_changed(prev, cur_tag, rr_paths)
    checks.append(AxisCheck(
        name="rule registry",
        declared=axes["rule registry"],
        moved=rr_moved,
        details=f"rule registry artifacts changed between {prev}..{cur_tag}: {rr_moved}",
    ))

    # ── Exit codes movement ──────────────────────────────────────────
    exit_paths = _existing_paths(prev, cur_tag, [
        "tests/contracts/exit_code_policy_manifest.json",
        "src/code_audit/policy/exit_codes.py",
    ])
    exit_moved = any_changed(prev, cur_tag, exit_paths)
    checks.append(AxisCheck(
        name="exit codes",
        declared=axes["exit codes"],
        moved=exit_moved,
        details=f"exit code policy changed between {prev}..{cur_tag}: {exit_moved}",
    ))

    # ── Confidence movement ──────────────────────────────────────────
    prev_conf = read_confidence_logic_version(prev)
    cur_conf = read_confidence_logic_version(cur_tag)
    conf_bumped = prev_conf is not None and cur_conf is not None and prev_conf != cur_conf
    conf_paths = _existing_paths(prev, cur_tag, [
        "tests/contracts/confidence_golden_manifest.json",
        "tests/contracts/confidence_policy_manifest.json",
        "src/code_audit/insights/confidence.py",
    ])
    conf_moved_files = any_changed(prev, cur_tag, conf_paths)
    conf_moved = conf_bumped or conf_moved_files
    checks.append(AxisCheck(
        name="confidence",
        declared=axes["confidence"],
        moved=conf_moved,
        details=(
            f"confidence_logic_version bumped: {conf_bumped} "
            f"(prev={prev_conf}, cur={cur_conf}); "
            f"files changed: {conf_moved_files}"
        ),
    ))

    # ── Web API movement (OpenAPI-only) ──────────────────────────────
    # Internal web_api code refactors do NOT count as contract movement.
    # Only OpenAPI contract artifacts prove public HTTP surface change.
    openapi_snapshot = "docs/openapi.json"
    openapi_schema = "schemas/openapi.schema.json"

    snapshot_exists = _file_exists_in_either(prev, cur_tag, openapi_snapshot)
    schema_oa_exists = _file_exists_in_either(prev, cur_tag, openapi_schema)

    if axes["web api"] == "yes" and not (snapshot_exists or schema_oa_exists):
        print(
            "ERROR: changelog truth enforcement failed — "
            "Web API: yes requires an OpenAPI contract artifact.",
            file=sys.stderr,
        )
        print(f"  Previous tag: {prev}", file=sys.stderr)
        print(f"  Current tag:  {cur_tag}", file=sys.stderr)
        print("", file=sys.stderr)
        print(
            "Missing OpenAPI artifacts in both tags. Expected at least one of:",
            file=sys.stderr,
        )
        print(f"  - {openapi_snapshot}", file=sys.stderr)
        print(f"  - {openapi_schema}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Fix:", file=sys.stderr)
        print(
            "  - Commit a stable OpenAPI snapshot (recommended: docs/openapi.json), "
            "then retag, OR",
            file=sys.stderr,
        )
        print(
            "  - Change 'Web API: yes' to 'Web API: no' if the public HTTP "
            "contract did not change.",
            file=sys.stderr,
        )
        return 1

    openapi_paths: list[str] = []
    if snapshot_exists:
        openapi_paths.append(openapi_snapshot)
    if schema_oa_exists:
        openapi_paths.append(openapi_schema)

    web_moved = any_changed(prev, cur_tag, openapi_paths) if openapi_paths else False
    web_details = f"openapi-only: checked={openapi_paths}, changed={web_moved}"
    checks.append(AxisCheck(
        name="web api",
        declared=axes["web api"],
        moved=web_moved,
        details=web_details,
    ))

    # ── Enforce truth ────────────────────────────────────────────────
    # Breaking axis is enforced by check_semver_breaking_gate.py; skip here.
    failures: list[tuple[str, str, str]] = []
    for c in checks:
        if c.name == "breaking":
            continue
        if c.declared == "yes" and not c.moved:
            failures.append((c.name, "declared yes but no movement detected", c.details))
        if args.enforce_no and c.declared == "no" and c.moved:
            failures.append((c.name, "declared no but movement detected", c.details))

    if failures:
        print("ERROR: changelog truth enforcement failed.", file=sys.stderr)
        print(f"  Previous tag: {prev}", file=sys.stderr)
        print(f"  Current tag:  {cur_tag}", file=sys.stderr)
        print("", file=sys.stderr)
        for name, reason, details in failures:
            print(f"- Axis '{name}': {reason}", file=sys.stderr)
            print(f"  Details: {details}", file=sys.stderr)
        print("", file=sys.stderr)
        print("Fix:", file=sys.stderr)
        print(
            "  - Update CHANGELOG axis declarations to match actual changes, OR",
            file=sys.stderr,
        )
        print(
            "  - Ensure the appropriate governed version/manifest changes are "
            "present for axes marked 'yes'.",
            file=sys.stderr,
        )
        print("", file=sys.stderr)
        print(
            "Tip: if you truly changed signal semantics, bump signal_logic_version "
            "and refresh manifests.",
            file=sys.stderr,
        )
        return 1

    # Summary
    summary_parts = []
    for c in checks:
        if c.name == "breaking":
            continue
        status = "moved" if c.moved else "stable"
        summary_parts.append(f"{c.name}={c.declared}({status})")
    print(f"OK: changelog truth enforcement passed for {cur_tag} (prev={prev}).")
    print(f"  Axes: {', '.join(summary_parts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
