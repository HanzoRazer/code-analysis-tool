#!/usr/bin/env python3
"""Refresh OpenAPI golden endpoint fixtures.

Reads the endpoint registry (``tests/contracts/openapi_golden_endpoints.json``),
hits each endpoint via FastAPI's ``TestClient``, applies the volatility scrubber,
and writes the golden fixture JSON under ``tests/fixtures/expected/``.

Usage:
  python scripts/refresh_openapi_golden_endpoints.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "contracts" / "openapi_golden_endpoints.json"
OPENAPI = ROOT / "docs" / "openapi.json"
SCRUB_POLICY = ROOT / "tests" / "contracts" / "openapi_golden_scrub_policy.json"
OUT_DIR = ROOT / "tests" / "fixtures" / "expected"
AUDIT_REPORT = ROOT / "tests" / "contracts" / "openapi_scrub_audit_report.json"


def must_load_json(p: Path) -> dict:
    if not p.exists():
        raise SystemExit(f"Missing required file: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def main() -> int:
    # ── Load registry + policy ───────────────────────────────────
    registry = must_load_json(REGISTRY)
    endpoints = registry.get("endpoints", [])
    if not endpoints:
        raise SystemExit("No endpoints defined in openapi_golden_endpoints.json")

    # Ensure OpenAPI snapshot exists (sanity check)
    if not OPENAPI.exists():
        raise SystemExit(
            f"Missing OpenAPI snapshot: {OPENAPI}\n"
            "Generate it first:\n"
            "  python scripts/refresh_openapi_snapshot.py --write\n"
        )

    from code_audit.contracts.openapi_scrub import (
        ScrubEvent,
        load_scrub_policy,
        scrub_json,
    )

    policy = load_scrub_policy(SCRUB_POLICY)

    # Import audit report helpers (local scripts/ module).
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "scripts"))
    from write_openapi_scrub_audit import (
        EndpointAudit,
        events_to_removed,
        write_report,
    )

    # ── Import FastAPI test client ───────────────────────────────
    try:
        from fastapi.testclient import TestClient  # type: ignore[import-untyped]
        from code_audit.web_api.main import app  # type: ignore[import-untyped]
    except ImportError as e:
        raise SystemExit(
            "Cannot import FastAPI app or TestClient.\n"
            "Install API extras:\n"
            "  python -m pip install -e '.[api]'\n"
            f"Import error: {e}\n"
        ) from e

    client = TestClient(app)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    written = 0
    audits: list[EndpointAudit] = []

    for ep in endpoints:
        method = ep["method"].upper()
        path = ep["path"]
        fixture_name = ep["fixture_name"]
        fixture_path = OUT_DIR / fixture_name

        # ── Hit the endpoint ─────────────────────────────────────
        resp = getattr(client, method.lower())(path)

        fixture: dict = {
            "endpoint": {"method": method, "path": path},
            "expected": {
                "status_code": resp.status_code,
            },
        }

        events: list[ScrubEvent] = []
        try:
            raw_json = resp.json()
            # Scrub volatile fields before writing into the golden contract.
            fixture["expected"]["json"] = scrub_json(
                raw_json, policy, path="/expected/json", events=events,
            )
        except Exception:
            fixture["expected"]["json"] = {"_non_json_text": resp.text}

        audits.append(
            EndpointAudit(
                endpoint=f"{method} {path}",
                fixture=f"tests/fixtures/expected/{fixture_name}",
                removed=events_to_removed(events),
            )
        )

        fixture_path.write_text(
            json.dumps(fixture, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        written += 1
        print(f"  wrote {fixture_path.relative_to(ROOT)}")

    # ── Write audit report ───────────────────────────────────────
    write_report(AUDIT_REPORT, audits)
    print(f"  wrote {AUDIT_REPORT.relative_to(ROOT)}")

    print(f"Refreshed {written} golden endpoint fixture(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
