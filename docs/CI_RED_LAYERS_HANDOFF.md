# CI Red Layers — Hand-off

**Date:** 2026-07-25
**Context:** main's `Run pytest (Python 3.11)` check has been red. Because the
suite runs with `--maxfail=1` (see `pyproject.toml addopts`), CI stops at the
*first* failing test, so only one red is ever visible at a time. Running the
full suite with `-o addopts=""` reveals a **layered stack** of independent
failures. This document records the layers, what has been fixed, and draws a
hard boundary around Layer 4, which is pre-existing debt with its own root cause.

## Test collection order matters

`--maxfail=1` + alphabetical file collection means the *first* failing test file
determines what CI reports. Rough order of the relevant files:

```
test_api_cli_parity_ci*        (Windows-stdout-CRLF noise; green on Linux)
test_cli_api_parity_js_ts*     (Layer 1 + Windows-stdout-CRLF noise)
test_confidence_*              (Layer 4)
test_exit_code_policy_*        (Layer 4)
test_openapi_scrub_*           (Layer 3)
test_schema_version_freeze     (Layer 2)
test_translator_policy_*       (Layer 4)
test_version_bump_enforcement  (Layer 4)
```

## The layers

| Layer | Symptom | Root cause | Status | Where |
|---|---|---|---|---|
| 1 | `test_js_ts_findings_present` — 0 JS/TS findings | CI installed `.[dev,api]` **without** the `treesitter` extra → `is_available()` False → analyzer silently returns `[]` | **Fixed** | PR #11 (`fix/js-ts-findings-parity`); identical fix also on PR #9 (`6008843`) |
| 2 | `test_schema_version_freeze` — non-envelope schema missing `schema_version.const` | Contradiction between two CI gates: `enforce_fallback_schema_sync.sh` demanded a **full mirror** while the freeze test demands **envelope-only**. Bot bulk-synced to satisfy the mirror gate, breaking freeze | **Fixed** | PR #10 (`fix/schema-freeze-oversync`) — reverts the over-sync + makes the mirror gate a **superset** check |
| 3 | `openapi_scrub_baseline` / `openapi_scrub_budgets` — hash mismatch | Manifests recorded **CRLF-baked** SHA-256 while `.gitattributes` pins LF and CI checks out LF | **Fixed** | PR #9 (`fix/bom-manifest-ast-drift`, commit `4113c53`) |
| 4 | `confidence_policy`, `confidence_golden`, `exit_code_policy`, `translator_policy`, `version_bump_enforcement`, `golden_manifest`, `openapi_classifier_manifest_gate` (×2), `contracts_bundle_is_fresh` | **Pre-existing manifest/AST-hash drift** — computed hash ≠ stored manifest hash. These are the *"5 product/policy reds"* PR #8's own description said to "expect… unrelated to this slice." | **OPEN — separate work** | `fix/ci-manifest-known-reds` (fresh investigation) |

## Not real (do not chase)

Three full-run failures are **Windows-stdout-CRLF** artifacts, not CI failures:
`test_api_cli_parity_ci_default_scan_sample_repo_exceptions`,
`test_default_mode_js_ts_matches_api`, `test_default_and_scan_subcommand_agree`.
Evidence: the **file-based** parity test (`test_scan_ci_js_ts_matches_api`)
passes; only the **stdout-based** ones fail (captured stdout carries `\r\n` on
Windows). Linux CI stdout has no `\r\n`, so these are green there.

## Boundary around Layer 4

Layer 4 is **pre-existing debt with its own root cause** and is being handled as
a **fresh scoped investigation** (`fix/ci-manifest-known-reds`), not a
continuation of the schema/js_ts work. Its resolution has governance weight: a
manifest-hash gate fails when "logic changed without bumping
`signal_logic_version`," so each red must be classified as **genuine logic
drift** (requires a version bump + manifest refresh) vs **environmental hash
drift** (regenerate the manifest, no semantic change). See the memory note
`bom-manifest-py311-ast-hash`. Do not fold Layer 4 into PRs #9/#10/#11.

## Merge dependency (layers 1–3)

- Layers 1–3 fixes are independent and correct, but **each PR's CI stays red
  until Layer 4 is resolved** (maxfail surfaces Layer 4 once 1–3 pass).
- Suggested order once Layer 4 lands: #10 (schema) → rebase #9 (inherits schema;
  carries CRLF + treesitter) → #11 folds in or is superseded by #9's `6008843`.
