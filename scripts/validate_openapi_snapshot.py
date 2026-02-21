#!/usr/bin/env python3
"""Validate that docs/openapi.json is a structurally valid OpenAPI document.

Uses ``openapi-spec-validator`` for full spec-level validation — not just
JSON-schema checks but also path/operation correctness, component reference
validity, parameter/requestBody/response coherence, etc.

Usage:
  python scripts/validate_openapi_snapshot.py                     # default path
  python scripts/validate_openapi_snapshot.py docs/openapi.json   # explicit path
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Validate an OpenAPI JSON snapshot against the OpenAPI spec.",
    )
    ap.add_argument(
        "path",
        nargs="?",
        default="docs/openapi.json",
        help="OpenAPI JSON snapshot path (default: docs/openapi.json)",
    )
    args = ap.parse_args()

    p = Path(args.path)
    if not p.exists():
        raise SystemExit(
            f"Missing OpenAPI snapshot: {p}\n"
            "Generate it with:\n"
            "  python scripts/refresh_openapi_snapshot.py --write\n"
        )

    doc = json.loads(p.read_text(encoding="utf-8"))

    # ── Spec validation (stronger than JSON-schema-only checks) ──
    try:
        from openapi_spec_validator import validate  # type: ignore[import-untyped]
    except ImportError as e:
        raise SystemExit(
            "Missing dependency: openapi-spec-validator\n"
            "Install with:\n"
            "  python -m pip install openapi-spec-validator\n"
        ) from e

    try:
        validate(doc)
    except Exception as e:
        raise SystemExit(
            "OpenAPI snapshot failed spec validation.\n"
            f"File: {p}\n"
            f"Error: {e}\n"
        )

    print(f"OK: OpenAPI snapshot is spec-valid: {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
