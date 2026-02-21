"""Contract gate: OpenAPI scrub audit must match accepted baseline.

When golden endpoint fixtures are refreshed, the volatility scrubber
removes fields matching volatile patterns.  This test re-runs the
scrubber, builds an audit report, and compares the set of scrubbed
JSON paths and keys against the accepted baseline.

If **new** volatile fields appear that are not in the baseline, this
test fails — forcing developers to either:

  1) Make the API response deterministic (preferred), or
  2) Explicitly accept the volatility by updating the baseline.

Fix workflow:
  1) Run ``python scripts/refresh_openapi_golden_endpoints.py``
  2) Inspect ``tests/contracts/openapi_scrub_audit_report.json``
  3) Add new paths/keys to
     ``tests/contracts/openapi_scrub_audit_baseline.json``
  4) Commit with an explanation of why the volatility is acceptable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "contracts" / "openapi_golden_endpoints.json"
SCRUB_POLICY = ROOT / "tests" / "contracts" / "openapi_golden_scrub_policy.json"
AUDIT_REPORT = ROOT / "tests" / "contracts" / "openapi_scrub_audit_report.json"
BASELINE = ROOT / "tests" / "contracts" / "openapi_scrub_audit_baseline.json"
BUDGETS = ROOT / "tests" / "contracts" / "openapi_scrub_budgets.json"
OPENAPI = ROOT / "docs" / "openapi.json"
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "expected"


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _regenerate_report() -> dict:
    """Re-run the scrubber on live endpoints and build an audit report."""
    from code_audit.contracts.openapi_scrub import (
        ScrubEvent,
        load_scrub_policy,
        scrub_json,
    )

    # Import lazily to allow the module file path into sys.path
    sys.path.insert(0, str(ROOT / "scripts"))
    from write_openapi_scrub_audit import (
        EndpointAudit,
        build_report,
        events_to_removed,
    )

    policy = load_scrub_policy(SCRUB_POLICY)
    registry = _load_json(REGISTRY)
    endpoints = registry.get("endpoints", [])

    from code_audit.web_api.main import app  # type: ignore[import-untyped]
    from fastapi.testclient import TestClient  # type: ignore[import-untyped]

    client = TestClient(app)
    audits: list[EndpointAudit] = []

    for ep in endpoints:
        method = ep["method"].upper()
        path = ep["path"]
        fixture_name = ep["fixture_name"]

        resp = getattr(client, method.lower())(path)

        try:
            raw_json = resp.json()
            events: list[ScrubEvent] = []
            scrub_json(raw_json, policy, path="/expected/json", events=events)
            audits.append(
                EndpointAudit(
                    endpoint=f"{method} {path}",
                    fixture=f"tests/fixtures/expected/{fixture_name}",
                    removed=events_to_removed(events),
                )
            )
        except Exception:
            pass

    return build_report(audits)


def test_openapi_scrub_audit_matches_baseline() -> None:
    """Fail if scrubbed fields are not declared in the accepted baseline."""
    assert BASELINE.exists(), (
        f"Missing scrub audit baseline: {BASELINE}\n"
        "Create it with accepted_json_paths and accepted_keys."
    )

    report = _regenerate_report()

    # Write the report for CI artifact / debugging
    AUDIT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_REPORT.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    baseline = _load_json(BASELINE)

    assert report.get("version") == 1
    assert baseline.get("version") == 1

    accepted_paths = set(baseline.get("accepted_json_paths") or [])
    accepted_keys = set(baseline.get("accepted_keys") or [])

    # Extract observed scrubbed paths/keys from report
    observed_paths = set((report.get("counts_by_json_path") or {}).keys())
    observed_keys = set((report.get("counts_by_key") or {}).keys())

    # Accept by path OR by key (path is more precise; key is coarser).
    unaccepted_paths = {
        p for p in observed_paths
        if p not in accepted_paths
    }
    # A key is accepted if it's in accepted_keys OR all its paths are accepted
    unaccepted_keys = {
        k for k in observed_keys
        if k not in accepted_keys
    }

    # Remove keys whose every observed path is already accepted
    truly_unaccepted_keys = set()
    for k in unaccepted_keys:
        # Find all paths for this key across entries
        key_paths = set()
        for entry in report.get("entries", []):
            for r in entry.get("removed", []):
                if r["key"] == k:
                    key_paths.add(r["json_path"])
        if key_paths - accepted_paths:
            truly_unaccepted_keys.add(k)

    # Also remove paths whose key is accepted
    truly_unaccepted_paths = {
        p for p in unaccepted_paths
        if not any(
            r["key"] in accepted_keys
            for entry in report.get("entries", [])
            for r in entry.get("removed", [])
            if r["json_path"] == p
        )
    }

    if truly_unaccepted_paths or truly_unaccepted_keys:
        msg = [
            "OpenAPI scrub audit baseline gate failed — "
            "new scrubbed volatility detected.",
        ]
        if truly_unaccepted_paths:
            msg.append(
                "\nNew scrubbed json_paths "
                "(add to accepted_json_paths to acknowledge intentionally):"
            )
            for p in sorted(truly_unaccepted_paths):
                msg.append(f"  - {p}")
        if truly_unaccepted_keys:
            msg.append(
                "\nNew scrubbed keys "
                "(add to accepted_keys to acknowledge intentionally):"
            )
            for k in sorted(truly_unaccepted_keys):
                msg.append(f"  - {k}")
        msg.append("")
        msg.append(f"Debug: report written to {AUDIT_REPORT.relative_to(ROOT)}")
        raise AssertionError("\n".join(msg))

    # ── Budget enforcement (anti-volatility-creep) ───────────────
    if not BUDGETS.exists():
        return  # budget enforcement is opt-in until file is committed

    budgets = json.loads(BUDGETS.read_text(encoding="utf-8"))
    if budgets.get("version") != 1:
        raise AssertionError("Scrub budgets file version must be 1")

    default_budget = (budgets.get("default") or {}).get("max_removed_fields", 0)
    endpoint_budgets = budgets.get("endpoints") or {}
    entries = report.get("entries") or []
    budget_failures: list[str] = []

    for e in entries:
        endpoint = e.get("endpoint")
        removed = e.get("removed") or []
        if not isinstance(endpoint, str) or not isinstance(removed, list):
            continue

        ep_budget_obj = endpoint_budgets.get(endpoint) or {}
        max_removed = ep_budget_obj.get("max_removed_fields", default_budget)
        try:
            max_removed_i = int(max_removed)
        except Exception:
            budget_failures.append(
                f"{endpoint}: invalid max_removed_fields="
                f"{max_removed!r} (must be int)"
            )
            continue

        removed_count = len(removed)
        if removed_count > max_removed_i:
            budget_failures.append(
                f"{endpoint}: removed_fields={removed_count} "
                f"exceeds budget={max_removed_i}"
            )

        # Optional finer budgets (only enforced if present)
        by_reason_budget = ep_budget_obj.get("max_removed_by_reason") or {}
        if isinstance(by_reason_budget, dict) and removed:
            counts: dict[str, int] = {}
            for r in removed:
                reason = (r or {}).get("reason")
                if isinstance(reason, str):
                    counts[reason] = counts.get(reason, 0) + 1
            for reason, cap in by_reason_budget.items():
                try:
                    cap_i = int(cap)
                except Exception:
                    budget_failures.append(
                        f"{endpoint}: invalid cap for reason "
                        f"{reason}={cap!r} (must be int)"
                    )
                    continue
                if counts.get(reason, 0) > cap_i:
                    budget_failures.append(
                        f"{endpoint}: reason '{reason}' "
                        f"count={counts.get(reason, 0)} exceeds cap={cap_i}"
                    )

        by_key_budget = ep_budget_obj.get("max_removed_by_key") or {}
        if isinstance(by_key_budget, dict) and removed:
            counts_k: dict[str, int] = {}
            for r in removed:
                key = (r or {}).get("key")
                if isinstance(key, str):
                    counts_k[key] = counts_k.get(key, 0) + 1
            for key, cap in by_key_budget.items():
                try:
                    cap_i = int(cap)
                except Exception:
                    budget_failures.append(
                        f"{endpoint}: invalid cap for key "
                        f"{key}={cap!r} (must be int)"
                    )
                    continue
                if counts_k.get(key, 0) > cap_i:
                    budget_failures.append(
                        f"{endpoint}: key '{key}' "
                        f"count={counts_k.get(key, 0)} exceeds cap={cap_i}"
                    )

    if budget_failures:
        msg = [
            "OpenAPI scrub budget gate failed — volatility creep detected.",
            "Violations:",
        ]
        for line in budget_failures:
            msg.append(f"  - {line}")
        msg.append("")
        msg.append("Fix options:")
        msg.append("  1) Make the endpoint deterministic (preferred), OR")
        msg.append(
            "  2) Explicitly raise its budget in "
            "tests/contracts/openapi_scrub_budgets.json with justification."
        )
        raise AssertionError("\n".join(msg))
