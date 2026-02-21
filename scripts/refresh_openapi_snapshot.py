#!/usr/bin/env python3
"""Generate a canonical OpenAPI snapshot from the FastAPI app.

Imports the FastAPI ``app`` object, calls ``app.openapi()``, canonicalises
the output (deterministic key order, sorted string lists, volatile keys
stripped), and either writes ``docs/openapi.json`` or checks that the
existing snapshot is fresh.

Usage:
  python scripts/refresh_openapi_snapshot.py           # check-only (exit 1 if stale)
  python scripts/refresh_openapi_snapshot.py --write    # write/overwrite docs/openapi.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "openapi.json"

# Keys that may change between runs without any real spec change.
_VOLATILE_KEYS = frozenset({"servers"})


def _stable(obj: Any) -> Any:
    """Return a recursively sorted, deterministic copy of *obj*.

    - dicts: sorted by key (volatile top-level keys stripped)
    - lists of strings: sorted
    - everything else: pass-through
    """
    if isinstance(obj, dict):
        return {k: _stable(v) for k, v in sorted(obj.items()) if k not in _VOLATILE_KEYS}
    if isinstance(obj, list):
        if obj and all(isinstance(i, str) for i in obj):
            return sorted(obj)
        return [_stable(i) for i in obj]
    return obj


def _get_openapi_doc() -> dict:
    """Import the FastAPI app and return its OpenAPI schema dict."""
    try:
        from code_audit.web_api.main import app  # type: ignore[import-untyped]
    except ImportError as e:
        raise SystemExit(
            "Cannot import FastAPI app.\n"
            "Install API extras first:\n"
            "  python -m pip install -e '.[api]'\n"
            f"Import error: {e}\n"
        ) from e
    return app.openapi()


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate or verify the canonical OpenAPI snapshot.",
    )
    ap.add_argument(
        "--write",
        action="store_true",
        help="Write docs/openapi.json (default: check-only)",
    )
    args = ap.parse_args()

    raw = _get_openapi_doc()
    canonical = json.dumps(_stable(raw), indent=2, sort_keys=True) + "\n"

    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(canonical, encoding="utf-8")
        print(f"Wrote {OUT}")
        return 0

    # Check-only mode
    if not OUT.exists():
        raise SystemExit(
            f"Missing OpenAPI snapshot: {OUT}\n"
            "Generate it with:\n"
            "  python scripts/refresh_openapi_snapshot.py --write\n"
        )

    existing = OUT.read_text(encoding="utf-8")
    if existing != canonical:
        raise SystemExit(
            "OpenAPI snapshot is stale.\n"
            f"File: {OUT}\n"
            "Regenerate with:\n"
            "  python scripts/refresh_openapi_snapshot.py --write\n"
        )

    print(f"OK: OpenAPI snapshot is fresh: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
