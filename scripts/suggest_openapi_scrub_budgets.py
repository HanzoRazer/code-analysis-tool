#!/usr/bin/env python3
"""Suggest OpenAPI scrub budgets from the current audit report.

Reads ``tests/contracts/openapi_scrub_audit_report.json`` and generates
a budget file where each endpoint's cap equals its current scrub removal
count (plus an optional buffer).

Usage:
  python scripts/suggest_openapi_scrub_budgets.py            # print to stdout
  python scripts/suggest_openapi_scrub_budgets.py --write     # overwrite budgets file
  python scripts/suggest_openapi_scrub_budgets.py --buffer 1  # add headroom
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "tests" / "contracts" / "openapi_scrub_audit_report.json"
OUT = ROOT / "tests" / "contracts" / "openapi_scrub_budgets.json"


def main() -> int:
    ap = argparse.ArgumentParser(description="Suggest scrub budgets from audit report")
    ap.add_argument(
        "--buffer", type=int, default=0,
        help="Add buffer to current counts (default 0)",
    )
    ap.add_argument(
        "--write", action="store_true",
        help="Write budgets file (default: print to stdout)",
    )
    args = ap.parse_args()

    if not REPORT.exists():
        raise SystemExit(
            "Missing audit report. Run:\n"
            "  python scripts/refresh_openapi_golden_endpoints.py"
        )

    report = json.loads(REPORT.read_text(encoding="utf-8"))
    entries = report.get("entries") or []

    endpoints: dict[str, dict] = {}
    for e in entries:
        endpoint = e.get("endpoint")
        removed = e.get("removed") or []
        if isinstance(endpoint, str) and isinstance(removed, list):
            endpoints[endpoint] = {
                "max_removed_fields": len(removed) + args.buffer,
            }

    budgets = {
        "version": 1,
        "default": {"max_removed_fields": 0},
        "endpoints": dict(sorted(endpoints.items())),
        "notes": (
            f"Suggested from {REPORT.name} with buffer={args.buffer}. "
            "Review before committing."
        ),
    }

    payload = json.dumps(budgets, indent=2, sort_keys=True) + "\n"
    if not args.write:
        print(payload)
        return 0

    OUT.write_text(payload, encoding="utf-8")
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
