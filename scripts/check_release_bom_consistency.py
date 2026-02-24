"""Validate release BOM consistency.

Checks all dist/ artifacts for hash coherence, schema identity matches,
schema ref-graph closure + edges, and provenance cross-references with
the diff report.

Uses the shared consistency engine from release_bom_consistency_lib.
Emits a governed JSON failure envelope via release_gate_json when
--json is passed.

Usage:
    python scripts/check_release_bom_consistency.py [--json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

from scripts.release_bom_consistency_runner import run_release_bom_consistency_check
from scripts.release_gate_json import (
    build_gate_failure_json,
    emit_gate_failure_human,
    emit_gate_failure_json,
    is_ci_true,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"

OUT_GATE_RESULT = DIST / "release_bom_consistency_result.json"


def main() -> int:
    json_mode = "--json" in sys.argv

    issues = run_release_bom_consistency_check()

    if not issues:
        if json_mode:
            print(json.dumps({"version": 1, "ok": True, "issue_count": 0, "issues": []}, indent=2, sort_keys=True))
        else:
            print("[bom-consistency] OK: all checks passed.")
        return 0

    # Build governed JSON envelope
    gate_json = build_gate_failure_json(
        kind="release_bom_consistency_failed",
        details=issues,
    )

    # Write gate result file
    OUT_GATE_RESULT.parent.mkdir(parents=True, exist_ok=True)
    OUT_GATE_RESULT.write_text(
        json.dumps(gate_json, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if json_mode:
        emit_gate_failure_json(gate_json)
    else:
        emit_gate_failure_human(gate_json)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
