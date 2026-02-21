#!/usr/bin/env python3
"""Build and write deterministic OpenAPI scrub audit reports.

Used by ``scripts/refresh_openapi_golden_endpoints.py`` to record what
fields were removed during golden fixture generation, and by
``tests/test_openapi_scrub_audit_baseline.py`` to compare against the
accepted baseline.

Report format (version 1):
  - totals (endpoints, removed_fields_total)
  - counts_by_reason, counts_by_key, counts_by_json_path
  - per-endpoint entries with sorted removal lists

Everything is deterministic (stable key sort, stable entry sort) so the
report is diffable and committable.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from code_audit.contracts.openapi_scrub import ScrubEvent


def _stable_dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


@dataclass(frozen=True)
class EndpointAudit:
    """Scrub events for a single endpoint fixture."""

    endpoint: str
    fixture: str
    removed: list[dict[str, str]]


def events_to_removed(events: list[ScrubEvent]) -> list[dict[str, str]]:
    """Convert ``ScrubEvent`` list to the dict format used in reports."""
    return [
        {
            "json_path": e.json_path,
            "key": e.key,
            "reason": e.reason,
            "value_preview": e.value_preview,
        }
        for e in events
    ]


def build_report(entries: list[EndpointAudit]) -> dict[str, Any]:
    """Build the full audit report dict from endpoint audit entries."""
    totals = {
        "endpoints": len(entries),
        "removed_fields_total": sum(len(e.removed) for e in entries),
    }

    by_reason: dict[str, int] = defaultdict(int)
    by_key: dict[str, int] = defaultdict(int)
    by_path: dict[str, int] = defaultdict(int)

    for e in entries:
        for r in e.removed:
            by_reason[r["reason"]] += 1
            by_key[r["key"]] += 1
            by_path[r["json_path"]] += 1

    return {
        "version": 1,
        "totals": totals,
        "counts_by_reason": dict(sorted(by_reason.items())),
        "counts_by_key": dict(sorted(by_key.items())),
        "counts_by_json_path": dict(sorted(by_path.items())),
        "entries": [
            {
                "endpoint": e.endpoint,
                "fixture": e.fixture,
                "removed": sorted(
                    e.removed,
                    key=lambda x: (x["json_path"], x["key"], x["reason"]),
                ),
            }
            for e in sorted(entries, key=lambda x: x.endpoint)
        ],
    }


def write_report(path: Path, entries: list[EndpointAudit]) -> None:
    """Write the audit report to *path* (deterministic JSON)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_stable_dump(build_report(entries)), encoding="utf-8")
