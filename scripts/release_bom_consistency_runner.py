"""Shared BOM consistency runner.

Provides run_release_bom_consistency_check() used by both:
- scripts/check_release_bom_consistency.py (standalone)
- scripts/check_release_bom_generator_gate.py (preflight, in-process)
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.release_bom_consistency_lib import (
    check_release_bom_object_against_dist,
    issue,
)

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
BOM_PATH = DIST / "release_bom.json"


def run_release_bom_consistency_check(
    *,
    bom_obj: Optional[Dict[str, Any]] = None,
    root: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """Run the full BOM consistency check and return issues list.

    If bom_obj is None, loads from dist/release_bom.json.
    """
    r = root or ROOT
    d = r / "dist"

    if bom_obj is None:
        bom_path = d / "release_bom.json"
        if not bom_path.exists():
            return [issue("missing_file", "dist/release_bom.json", "present", "missing")]
        try:
            bom_obj = json.loads(bom_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            return [issue("invalid_json", "dist/release_bom.json", "valid JSON", str(e))]

    return check_release_bom_object_against_dist(
        bom_obj=bom_obj,
        root=r,
        dist=d,
    )
