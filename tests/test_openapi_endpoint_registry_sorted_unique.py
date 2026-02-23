"""Contract test: endpoint registry must be sorted and unique.

Enforces:
  - no duplicate (METHOD, path) entries
  - entries sorted deterministically by (path, method)
  - validates via the canonical extraction function (method + verb checks)
"""
from __future__ import annotations

import json
from pathlib import Path

from tests.test_release_openapi_registry_matches_snapshot import _extract_registry_endpoints


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "tests" / "contracts" / "openapi_golden_endpoints.json"


def _load_registry() -> dict:
    assert REGISTRY_PATH.exists(), f"Missing endpoint registry: {REGISTRY_PATH.relative_to(ROOT)}"
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def test_endpoint_registry_entries_unique_and_sorted() -> None:
    reg = _load_registry()
    endpoints = _extract_registry_endpoints(reg)
    assert endpoints, "Endpoint registry must contain at least one endpoint"

    # Uniqueness
    seen: set[tuple[str, str]] = set()
    dups: list[tuple[str, str]] = []
    for ep in endpoints:
        if ep in seen:
            dups.append(ep)
        else:
            seen.add(ep)
    if dups:
        lines = ["Endpoint registry contains duplicate endpoints (METHOD, path):"]
        lines.extend([f"- {m} {p}" for (m, p) in dups])
        lines.append("")
        lines.append("Fix: remove duplicates from tests/contracts/openapi_golden_endpoints.json")
        raise AssertionError("\n".join(lines))

    # Sorted order (path, then method)
    sorted_endpoints = sorted(endpoints, key=lambda t: (t[1], t[0]))
    if endpoints != sorted_endpoints:
        lines = ["Endpoint registry must be sorted by (path, method)."]
        lines.append("Expected order:")
        for m, p in sorted_endpoints:
            lines.append(f"- {m} {p}")
        lines.append("")
        lines.append("Fix: sort the endpoints deterministically.")
        raise AssertionError("\n".join(lines))
