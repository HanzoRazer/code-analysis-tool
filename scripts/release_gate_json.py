"""Shared release gate JSON envelope builder.

Provides helpers to construct and emit governed failure JSON payloads
for all release gate scripts.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List


def is_ci_true() -> bool:
    """Return True if running in CI (GitHub Actions, etc.)."""
    return os.environ.get("CI", "").lower() in ("true", "1", "yes")


def build_gate_failure_json(
    *,
    kind: str,
    path: str,
    expected: Any,
    got: Any,
    details: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build a governed gate failure payload conforming to the release gate envelope."""
    return {
        "kind": kind,
        "path": path,
        "expected": expected,
        "got": got,
        "ci": is_ci_true(),
        "details": details,
    }


def emit_gate_failure_json(result: Dict[str, Any], file: Any = None) -> None:
    """Emit gate failure payload as JSON to stderr (or specified file)."""
    out = file if file is not None else sys.stderr
    print(json.dumps(result, indent=2, sort_keys=True), file=out)


def emit_gate_failure_human(result: Dict[str, Any], *, prefix: str = "gate") -> None:
    """Emit gate failure payload as human-readable text to stderr."""
    details = result.get("details") or []
    kind = result.get("kind", "?")
    print(f"[{prefix}] FAIL ({kind}): {len(details)} issue(s) found.", file=sys.stderr)
    for i, d in enumerate(details):
        dk = d.get("kind", "?")
        dp = d.get("path", "?")
        de = d.get("expected", "?")
        dg = d.get("got", "?")
        print(f"  [{i + 1}] {dk}: {dp}  expected={de}  got={dg}", file=sys.stderr)
