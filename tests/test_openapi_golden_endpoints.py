"""Contract test: OpenAPI golden endpoint responses must match fixtures.

Hits each endpoint defined in ``tests/contracts/openapi_golden_endpoints.json``
via ``TestClient``, applies the same volatility scrubber used when the
fixtures were written, and asserts the scrubbed runtime response matches
the stored golden fixture.

Fix workflow (when this test fails):
  1)  If the response shape changed intentionally → bump
      ``signal_logic_version`` if the change is semantic.
  2)  Refresh fixtures:
        python scripts/refresh_openapi_golden_endpoints.py
  3)  Review the diff, commit updated fixtures.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "contracts" / "openapi_golden_endpoints.json"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "expected"
SCRUB_POLICY = ROOT / "tests" / "contracts" / "openapi_golden_scrub_policy.json"


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _endpoint_ids() -> list[dict]:
    """Return endpoint dicts from the registry (used for parametrize)."""
    if not REGISTRY.exists():
        return []
    reg = _load_json(REGISTRY)
    return reg.get("endpoints", [])


@pytest.mark.parametrize(
    "ep",
    _endpoint_ids(),
    ids=lambda ep: f"{ep['method']} {ep['path']}",
)
def test_openapi_golden_endpoints_match_runtime(ep: dict) -> None:
    """Each registered endpoint's scrubbed response must match its golden fixture."""
    from fastapi.testclient import TestClient  # type: ignore[import-untyped]
    from code_audit.contracts.openapi_scrub import load_scrub_policy, scrub_json
    from code_audit.web_api.main import app  # type: ignore[import-untyped]

    policy = load_scrub_policy(SCRUB_POLICY)
    client = TestClient(app)

    method = ep["method"].upper()
    path = ep["path"]
    fixture_name = ep["fixture_name"]
    fixture_path = FIXTURE_DIR / fixture_name

    assert fixture_path.exists(), (
        f"Missing golden fixture: {fixture_path}\n"
        "Generate it with:\n"
        "  python scripts/refresh_openapi_golden_endpoints.py\n"
    )

    fixture = _load_json(fixture_path)
    exp = fixture.get("expected", {})

    # ── Hit the endpoint ─────────────────────────────────────────
    resp = getattr(client, method.lower())(path)

    # ── Status code ──────────────────────────────────────────────
    assert resp.status_code == exp.get("status_code"), (
        f"Status code mismatch for {method} {path}: "
        f"got {resp.status_code}, expected {exp.get('status_code')}"
    )

    # ── JSON body (scrubbed) ─────────────────────────────────────
    try:
        got_json = scrub_json(resp.json(), policy, path="/expected/json")
    except Exception:
        got_json = {"_non_json_text": resp.text}

    assert got_json == exp.get("json"), (
        f"JSON mismatch for {method} {path}\n"
        f"Fixture: {fixture_path}\n"
        f"Got:      {json.dumps(got_json, sort_keys=True)}\n"
        f"Expected: {json.dumps(exp.get('json'), sort_keys=True)}\n"
    )
