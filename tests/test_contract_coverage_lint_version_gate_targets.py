"""Coverage lint: dedicated version gates reference correct artifact files.

Ensures per-artifact (non-umbrella) version gate tests actually reference
the artifact they claim to guard, and do **not** reference the other artifact's
tokens (no ambiguity).  This prevents miswiring baseline <-> budgets via
copy/paste accidents.

Policy:
  - Baseline version gate must contain ``openapi_scrub_audit_baseline.json``
    and must **NOT** contain ``openapi_scrub_budgets.json``.
  - Budgets version gate must contain ``openapi_scrub_budgets.json``
    and must **NOT** contain ``openapi_scrub_audit_baseline.json``.

Cross-reference:
  The full PROMOTED_ARTIFACTS mapping lives in
  tests/test_contract_manifest_self_consistency.py.  This file duplicates
  only the minimal mapping needed for cross-token lint.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The umbrella version gate applies to all promoted artifacts (non-dedicated).
UMBRELLA_VERSION_GATE = "tests/test_golden_manifest_requires_signal_logic_bump.py"

# Artifacts that must have exactly one dedicated (non-umbrella) version gate,
# together with their declared dedicated version gate files.
# Keep in sync with PROMOTED_ARTIFACTS in test_contract_manifest_self_consistency.py.
DEDICATED_VERSION_GATES: dict[str, list[str]] = {
    "tests/contracts/openapi_scrub_audit_baseline.json": [
        "tests/test_openapi_scrub_baseline_requires_signal_logic_bump.py",
    ],
    "tests/contracts/openapi_scrub_budgets.json": [
        "tests/test_openapi_scrub_budgets_requires_signal_logic_bump.py",
    ],
}


def _version_gates_for_artifact(artifact_path: str) -> list[str]:
    """Return the non-umbrella version gates declared for *artifact_path*."""
    return DEDICATED_VERSION_GATES.get(artifact_path, [])


def _forbidden_tokens_for_artifact(artifact_path: str) -> list[str]:
    """
    Cross-token forbiddance (no ambiguity):
    A dedicated version gate for one artifact must not reference the other artifact's tokens.
    """
    name = Path(artifact_path).name
    if name == "openapi_scrub_audit_baseline.json":
        return [
            "openapi_scrub_budgets.json",
            "openapi_scrub_budgets_manifest.json",
        ]
    if name == "openapi_scrub_budgets.json":
        return [
            "openapi_scrub_audit_baseline.json",
            "openapi_scrub_baseline_manifest.json",
        ]
    return []


def _required_tokens_for_artifact(artifact_path: str) -> list[str]:
    """Return the string tokens we expect a dedicated version gate to contain.

    ``[0]``  is the primary artifact filename (mandatory).
    ``[1:]`` are optional robustness tokens — the lint warns if absent
    but does not hard-fail (so existing tests pass without disruption).

    Current mapping:
      - baseline → [openapi_scrub_audit_baseline.json, openapi_scrub_baseline_manifest.json]
      - budgets  → [openapi_scrub_budgets.json, openapi_scrub_budgets_manifest.json]
    """
    name = Path(artifact_path).name
    if name == "openapi_scrub_audit_baseline.json":
        return [
            "openapi_scrub_audit_baseline.json",
            "openapi_scrub_baseline_manifest.json",
        ]
    if name == "openapi_scrub_budgets.json":
        return [
            "openapi_scrub_budgets.json",
            "openapi_scrub_budgets_manifest.json",
        ]
    # Fallback: just require the artifact filename.
    return [name]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ── Tests ───────────────────────────────────────────────────────────────


def test_dedicated_version_gates_reference_correct_artifact_files() -> None:
    """
    Coverage lint:
    Ensure the per-artifact (non-umbrella) version gate test(s) actually reference
    the artifact they claim to guard, and do not reference the other artifact (no ambiguity).
    """
    failures: list[str] = []

    for artifact_path in DEDICATED_VERSION_GATES:
        gates = _version_gates_for_artifact(artifact_path)
        if not gates:
            failures.append(
                f"{artifact_path}: no dedicated (non-umbrella) version gates declared."
            )
            continue

        required_tokens = _required_tokens_for_artifact(artifact_path)
        forbidden_tokens = _forbidden_tokens_for_artifact(artifact_path)

        for gate_rel in gates:
            gate_path = ROOT / gate_rel
            if not gate_path.exists():
                failures.append(
                    f"{artifact_path}: dedicated version gate file missing: {gate_rel}"
                )
                continue

            src = _read_text(gate_path)

            # --- Required token checks ---
            primary = Path(artifact_path).name
            if primary not in src:
                failures.append(
                    f"{artifact_path}: dedicated version gate does not reference '{primary}': {gate_rel}"
                )
                continue

            # Optional robustness: if we expect a manifest token, require it too.
            # This catches cases where someone copied the test and only changed one constant.
            for t in required_tokens[1:]:
                if t not in src:
                    failures.append(
                        f"{artifact_path}: dedicated version gate missing expected token '{t}': {gate_rel}"
                    )

            # --- Forbidden cross-token checks (no ambiguity) ---
            for ft in forbidden_tokens:
                if ft in src:
                    failures.append(
                        f"{artifact_path}: dedicated version gate illegally references cross-token '{ft}': {gate_rel}"
                    )

    if failures:
        lines = ["Coverage lint failed: dedicated version gates are miswired or incomplete."]
        lines.extend(failures)
        lines.append("")
        lines.append("Fix:")
        lines.append("  - Each dedicated version gate must reference its own artifact tokens.")
        lines.append("  - Baseline gate: references openapi_scrub_audit_baseline, NOT budgets.")
        lines.append("  - Budgets gate: references openapi_scrub_budgets, NOT baseline.")
        raise AssertionError("\n".join(lines))
