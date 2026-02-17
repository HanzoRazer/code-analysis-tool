# Engineer Handback Report — code-analysis-tool

**Date:** 2026-02-14  
**Repo:** `github.com/HanzoRazer/code-analysis-tool`  
**Branch:** `main`  
**HEAD:** `82b93ef` (canonical marker block), `8476a28` (contract gate shipment)  
**Python:** 3.13.7  
**Package:** `code_audit` (installable from `src/`)  
**Test count:** 59+ test files, **714+ test cases** (all green at time of shipment)

---

## 1. Current Repo Layout

```
code-analysis-tool/
├── .github/
│   ├── CODEOWNERS
│   ├── copilot-instructions.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── SESSION_BOOKMARK.md
│   └── workflows/
│       ├── copy-lint.yml
│       ├── pytest.yml
│       └── ratchet.yml
├── baselines/
│   └── main.json                         # Structural debt baseline
├── cbsp21/                               # CBSP-21 governance pack
│   ├── patch_input.json
│   ├── patch_input.json.example
│   ├── patch_input.schema.json
│   ├── patch_input.template.json
│   └── README.md
├── ci/                                   # CI enforcement scripts
│   ├── enforce_fallback_schema_sync.sh
│   ├── enforce_schema_version_bump.sh
│   └── reject_stale_schema_duplicate.sh
├── # code_audit/ shim — DELETED (see §6)
├── # code_audit_2026-02-11_patched/ — DELETED (see §6)
├── docs/
│   ├── ALPHA_OMEGA_HANDOFF.md
│   ├── CONTRACT.md                       # Public stability contract
│   ├── DECISION_PATHS.md
│   ├── DEPLOYMENT_PLAN.md
│   ├── ORGANIZATION_PLAN.md
│   ├── patterns/
│   ├── REHYDRATION_SUMMARY.md
│   ├── support-matrix.md
│   └── TOOL_CATALOG.md
├── i18n/en/                              # Copy governance locale files
├── schemas/
│   ├── debt_snapshot.schema.json
│   ├── drift_budget_signal.schema.json    # ← NEW (drift budget signal v1)
│   ├── drift_budget_signal.example.json   # ← NEW (example artifact)
│   ├── run_result.schema.json
│   ├── signals_latest.schema.json
│   └── user_event.schema.json
├── scripts/
│   ├── copy_lint.py                      # i18n copy linter
│   ├── copy_lint_vibe_saas.py            # SaaS copy linter
│   ├── generate_drift_budget_signal.py   # ← NEW (signal generator)
│   ├── locale_parity.py
│   ├── refresh_baseline.py
│   ├── refresh_drift_budget_signal_manifest.py  # ← NEW (signal manifest)
│   ├── refresh_golden_manifest.py        # ← NEW (contract gate)
│   ├── refresh_logic_manifest.py         # ← NEW (contract gate)
│   ├── refresh_translator_policy_manifest.py  # ← NEW (contract gate)
│   ├── validate_drift_budget_signal.py   # ← NEW (signal validator)
│   └── validate_schema.py
├── src/code_audit/                       # ★ THE PACKAGE
│   ├── analyzers/                        # 8 analyzers (see §2)
│   ├── api.py                            # Public API surface
│   ├── contracts/                        # Safety fences
│   ├── core/                             # Config, discovery, runner
│   ├── data/                             # Bundled data files
│   ├── governance/                       # Deprecation, import ban, legacy, SDK
│   ├── insights/                         # Translator, confidence
│   ├── inventory/                        # Feature-flag hunting
│   ├── ml/                               # Bug predictor, clustering
│   ├── model/                            # Finding, RunResult, DebtInstance, Fence
│   ├── policy/                           # Threshold definitions
│   ├── reports/                          # Markdown, HTML, JSON export
│   ├── run_result.py
│   ├── scaffold.py
│   ├── strangler/                        # Debt detector, registry, plan gen
│   ├── ui/                               # Terminal dashboard
│   ├── utils/
│   ├── web_api/                          # FastAPI endpoints
│   ├── __init__.py
│   └── __main__.py                       # CLI entrypoint
├── tests/                                # 56 test files (see §3)
│   ├── contracts/                        # ← NEW: 3 contract manifests
│   ├── fixtures/                         # Golden expected files, repos
│   ├── rescue/
│   ├── template/
│   └── web_api/
├── BASELINE.md
├── CONTRIBUTING.md
├── DEVELOPER_HANDOFF.md                  # Prior handoff (2026-02-11)
├── Makefile
├── pyproject.toml
├── # RESCUE_PLAN.* — moved to docs/archive/ (see §6)
```

---

## 2. Analyzer Registry (8 registered)

All analyzers live in `src/code_audit/analyzers/` and are registered in `_DEFAULT_ANALYZERS` in `src/code_audit/api.py`:

| # | Class | Module | Version | Logic Hash (sha256, first 12) |
|---|---|---|---|---|
| 1 | `ComplexityAnalyzer` | `complexity.py` | 1.0.0 | `8a9628309549` |
| 2 | `DeadCodeAnalyzer` | `dead_code.py` | 1.0.0 | `e2b51f7ad1d5` |
| 3 | `DuplicationAnalyzer` | `duplication.py` | 1.0.0 | `154c3907d130` |
| 4 | `ExceptionsAnalyzer` | `exceptions.py` | 1.0.0 | `f1437c28c3b8` |
| 5 | `FileSizesAnalyzer` | `file_sizes.py` | 1.1.0 | `49c38f062113` |
| 6 | `GlobalStateAnalyzer` | `global_state.py` | 1.0.0 | `50c60b686d29` |
| 7 | `RoutersAnalyzer` | `routers.py` | 1.0.0 | `aacf8a413e59` |
| 8 | `SecurityAnalyzer` | `security.py` | 1.0.0 | `9b67594f208a` |

**Contract:** `test_analyzer_registry_contract.py` ensures `_DEFAULT_ANALYZERS` is exhaustive (discovers all concrete `BaseAnalyzer` subclasses via `pkgutil`).

---

## 3. Contract Enforcement Gates (Shipped in `8476a28`)

Six new CI contract gates were added. Each test is a **hard gate** — if it fails, CI blocks the merge.

### 3.1 Analyzer Registry Contract

| | |
|---|---|
| **Test** | `tests/test_analyzer_registry_contract.py` |
| **What it guards** | Every concrete `BaseAnalyzer` subclass must appear in `_DEFAULT_ANALYZERS` |
| **Enforcement** | Scan `src/code_audit/analyzers/` via `pkgutil`, compare to `api._DEFAULT_ANALYZERS` |
| **When it fails** | A new analyzer module is added but not registered in `api.py` |

### 3.2 Version Bump Enforcement (Logic Manifest)

| | |
|---|---|
| **Test** | `tests/test_version_bump_enforcement.py` |
| **Manifest** | `tests/contracts/logic_manifest.json` |
| **Refresh** | `python scripts/refresh_logic_manifest.py` |
| **What it guards** | If an analyzer's semantic logic changes, its `version` must be bumped |
| **Enforcement** | AST-normalized hash of each analyzer module (strips docstrings + version literals) |
| **When it fails** | Editing analyzer code without bumping its `.version` attribute |

### 3.3 Golden Fixtures Manifest

| | |
|---|---|
| **Test** | `tests/test_golden_manifest_requires_signal_logic_bump.py` |
| **Manifest** | `tests/contracts/golden_fixtures_manifest.json` |
| **Refresh** | `python scripts/refresh_golden_manifest.py` |
| **What it guards** | Golden expected-output files can only change if `signal_logic_version` is bumped |
| **Enforcement** | SHA-256 hash of every `tests/fixtures/expected/*.json` file |
| **When it fails** | Editing a golden fixture without bumping `signal_logic_version` in `run_result.py` |
| **Golden files** | 14 files (clean, hot, specific-analyzer result fixtures) |

### 3.4 Translator Policy Gate

| | |
|---|---|
| **Test** | `tests/test_translator_policy_requires_signal_logic_bump.py` |
| **Manifest** | `tests/contracts/translator_policy_manifest.json` |
| **Refresh** | `python scripts/refresh_translator_policy_manifest.py` |
| **What it guards** | Semantic policy surface of `insights/translator.py` |
| **Enforcement** | AST hash of policy-affecting functions + constants |
| **Policy surface** | Functions: `_severity_rank`, `_worst_severity`, `_risk_from_worst_severity`, `_urgency_from_severity`, `_group_key`, `findings_to_signals` |
| **Constant patterns** | `_COPY_PREFIX`, `EVIDENCE_*`, `*_RULE_ORDER`, `*_RULE_IDS`, `*_SUMMARY_KEYS`, `*_EVIDENCE_KEYS` |
| **When it fails** | Changing severity mappings, grouping logic, or copy-key constants without bumping `signal_logic_version` |

### 3.5 Translator Copy-Key Contract

| | |
|---|---|
| **Test** | `tests/test_translator_copy_key_contract_fields.py` |
| **What it guards** | Every signal emitted at runtime must include `title_key`, `summary_key`, `why_key`, and `action.text_key` |
| **Enforcement** | Runs `scan_project()` against `sample_repo_exceptions` fixture and checks all signals |
| **When it fails** | `findings_to_signals()` produces a signal missing a required copy-key field |

### 3.6 API / CLI Parity

| | |
|---|---|
| **Test** | `tests/test_api_cli_parity_ci.py` |
| **What it guards** | `scan_project()` API and `code-audit <path> --ci` CLI produce identical JSON output |
| **Enforcement** | Runs both paths against `sample_repo_exceptions`, deep-compares dicts |
| **When it fails** | API and CLI diverge on output shape, ordering, or values |

### 3.7 Drift Budget Signal Gate

| | |
|---|---|
| **Test** | `tests/test_drift_budget_signal_requires_signal_logic_bump.py` |
| **Manifest** | `tests/contracts/drift_budget_signal_manifest.json` |
| **Refresh** | `python scripts/refresh_drift_budget_signal_manifest.py` |
| **What it guards** | Schema, generator, and validator for the `drift_budget_signal_v1` CI artifact |
| **Enforcement** | Composite SHA-256 of `schemas/drift_budget_signal.schema.json`, `scripts/generate_drift_budget_signal.py`, `scripts/validate_drift_budget_signal.py` |
| **When it fails** | Changing the signal schema, generator logic, or validator without bumping `signal_logic_version` |

---

## 4. Key Versioning Anchors

| Anchor | Location | Current Value |
|---|---|---|
| `signal_logic_version` | `src/code_audit/model/run_result.py:32` | `"signals_v2"` |
| `engine_version` | `src/code_audit/model/run_result.py:31` | `"engine_v1"` |
| `tool_version` (package) | `pyproject.toml` | `"0.1.0"` |
| Schema: `run_result` | `schemas/run_result.schema.json` | `run_result_v1` |
| Schema: `debt_snapshot` | `schemas/debt_snapshot.schema.json` | `debt_snapshot_v1` |
| Schema: `drift_budget_signal` | `schemas/drift_budget_signal.schema.json` | `drift_budget_signal_v1` |

**Bump rules:**

- Editing analyzer logic → bump analyzer `.version` + refresh logic manifest
- Editing signal generation, severity mapping, copy keys → bump `signal_logic_version` + refresh ALL manifests
- Editing drift budget signal schema/generator/validator → bump `signal_logic_version` + refresh drift budget signal manifest
- Editing output shape → bump schema version + update golden fixtures

---

## 5. Downstream Dependency: `code-rescue-tool`

A separate repository at `github.com/HanzoRazer/code-rescue-tool` consumes `run_result_v1` JSON output from this repo.

| | |
|---|---|
| **Package** | `code_rescue` |
| **Dependency** | `code-analysis-tool @ git+https://github.com/HanzoRazer/code-analysis-tool` |
| **CLI** | `code-rescue = "code_rescue.__main__:main"` |
| **Input** | `run_result_v1` JSON (piped from `code-audit` CLI) |
| **Build** | `hatchling` (vs `setuptools` in this repo) |

### code-rescue-tool structure

```
src/code_rescue/
├── fixers/          # Auto-fix modules
├── ingest/          # RunResult JSON parser
├── model/           # Downstream data model
├── planner/         # Rescue plan generator
├── __init__.py
└── __main__.py
contracts/
└── run_result.schema.json    # ← Copy of this repo's schema
tests/
├── test_ingest_run_result.py
└── test_rescue_planner.py
```

### Supported rule IDs in code-rescue-tool

```
DC_UNREACHABLE_001   DC_IF_FALSE_001      DC_ASSERT_FALSE_001
GST_MUTABLE_DEFAULT_001  GST_MUTABLE_MODULE_001  GST_GLOBAL_KEYWORD_001
SEC_HARDCODED_SECRET_001  SEC_EVAL_001     SEC_SUBPROCESS_SHELL_001
SEC_SQL_INJECTION_001     SEC_PICKLE_LOAD_001     SEC_YAML_UNSAFE_001
```

**Risk:** If `run_result_v1` schema changes here, `code-rescue-tool`'s `ingest/` layer and `contracts/run_result.schema.json` will break.

**Mitigations (shipped):**
- `docs/contracts_bundle.json` — producer-side bundle of SHA-256 hashes for downstream-consumed artifacts (run_result_schema, rule_registry, rule_registry_schema).
- `tests/test_contracts_bundle_is_fresh.py` — ensures bundle stays current with source artifacts.
- `.github/workflows/contract-parity-main-observer.yml` — nightly drift detector that opens/reopens a rolling GitHub Issue when parity against upstream `main` fails, and auto-closes it when parity returns to green.

---

## 6. Workspace Artifacts ~~Requiring Clarification~~ — RESOLVED

### 6.1 `code_audit_2026-02-11_patched/` — DELETED

Frozen snapshot (~160 files) removed from `main`. Pre-cleanup state preserved via git tag `snapshot-2026-02-11`. Git history retains full content.

### 6.2 `code_audit/` top-level shim — DELETED

Orphaned legacy shim (only `__init__.py` + `__main__.py`). Verified zero references in tests, CI workflows, Makefile, or docs before removal. `pyproject.toml` package-dir points to `src/`; installed entrypoint is unaffected.

### 6.3 `RESCUE_PLAN.md` / `RESCUE_PLAN.json` — ARCHIVED

Moved to `docs/archive/` with historical-artifact banner. Original files referenced `repo/src` (nonexistent path). Retained for historical reference only.

---

## 7. CI Workflows

| Workflow | File | Purpose |
|---|---|---|
| **pytest** | `.github/workflows/pytest.yml` | Runs full test suite |
| **copy-lint** | `.github/workflows/copy-lint.yml` | i18n copy governance linter |
| **ratchet** | `.github/workflows/ratchet.yml` | Debt snapshot + compare vs `baselines/main.json` |
| **rule-registry-sync** | `.github/workflows/rule-registry-sync.yml` | Rule registry schema + parity enforcement |
| **contract-parity-main-observer** | `.github/workflows/contract-parity-main-observer.yml` | Nightly drift detector against upstream `main` (non-blocking). Opens/reopens a rolling GitHub Issue on drift; auto-closes on green. Emits `drift_budget_signal_v1` artifact. |

CI enforcement shell scripts in `ci/`:
- `enforce_fallback_schema_sync.sh`
- `enforce_schema_version_bump.sh`
- `reject_stale_schema_duplicate.sh`

---

## 8. How to Bump Versions (Cheat Sheet)

### Adding a new analyzer

1. Create `src/code_audit/analyzers/new_analyzer.py`
2. Add import + class to `_DEFAULT_ANALYZERS` in `api.py` (keep alphabetical)
3. Run `python scripts/refresh_logic_manifest.py`
4. Run `python -m pytest tests/test_analyzer_registry_contract.py tests/test_version_bump_enforcement.py`

### Changing analyzer logic

1. Edit the analyzer module
2. Bump its `.version` attribute (e.g., `"1.0.0"` → `"1.1.0"`)
3. Run `python scripts/refresh_logic_manifest.py`
4. Run `python -m pytest tests/test_version_bump_enforcement.py`

### Changing signal generation / severity mapping

1. Edit `insights/translator.py` or `model/run_result.py`
2. Bump `signal_logic_version` in `run_result.py` (e.g., `"signals_v1"` → `"signals_v2"`)
3. Regenerate golden fixtures: `python -m pytest tests/test_golden_fixtures.py` (expected failures → update fixtures)
4. Run all three refresh scripts:
   ```bash
   python scripts/refresh_logic_manifest.py
   python scripts/refresh_golden_manifest.py
   python scripts/refresh_translator_policy_manifest.py
   ```
5. Run full suite: `python -m pytest`

### Refreshing the debt baseline

```bash
python scripts/refresh_baseline.py
# Commit baselines/main.json with explanation
```

---

## 9. Questions for the Returning Engineer

### Workspace Layout — RESOLVED

1. ~~**Patched snapshot fate:**~~ **RESOLVED.** Deleted `code_audit_2026-02-11_patched/` from `main`. Tagged `snapshot-2026-02-11` before deletion. Git history is the archive.

2. ~~**Legacy shim cleanup:**~~ **RESOLVED.** Deleted root-level `code_audit/` shim. Verified zero references in tests, CI, Makefile, or docs. No external consumers identified.

3. ~~**Stale rescue artifacts:**~~ **RESOLVED.** Moved `RESCUE_PLAN.md` and `RESCUE_PLAN.json` to `docs/archive/` with historical-artifact banner.

### Cross-Repo Contracts

4. **code-rescue-tool schema sync:** `code-rescue-tool` carries its own copy of `run_result.schema.json`. There is no automated contract test ensuring schema parity between the two repos. Do you want a CI job or pre-commit hook that validates the downstream schema stays in sync? Options:
   - Submodule / shared package for the schema
   - CI job in `code-rescue-tool` that fetches and compares
   - GitHub Action in this repo that pings downstream on schema changes

5. **Rule ID registry:** `code-rescue-tool` supports 12 specific rule IDs (DC_*, GST_*, SEC_*). Are there plans to expand coverage to complexity, duplication, exceptions, router, or file-size rules? Should there be a shared rule-ID registry between the two repos?

### Versioning & Release

6. **Package version:** `pyproject.toml` still shows `version = "0.1.0"`. The test suite has 611+ cases, 8 analyzers, a full API surface, and a web API. Is a `1.0.0` release planned? What are the remaining blockers?

7. **signal_logic_version alignment:** If `signal_logic_version` bumps to `"signals_v2"`, `code-rescue-tool`'s ingest layer will need to handle both `v1` and `v2` formats. Is there a migration strategy in place, or should breaking changes be avoided until rescue-tool is updated?

### CI & Testing

8. **CI workflow activation:** The three GitHub Actions workflows (`pytest.yml`, `copy-lint.yml`, `ratchet.yml`) are defined but — are they active on the repo? Have they been tested against the current `main` branch? The contract gate tests added in `8476a28` should be included in the pytest CI matrix.

9. **Test fixture repos:** `tests/fixtures/repos/` and `tests/fixtures/sample_repo_*` directories contain synthetic repos for testing. Are these sufficient for edge cases, or should additional fixtures be created for router/duplication/complexity scenarios?

10. **maxfail=1 in pyproject.toml:** The pytest config sets `--maxfail=1` which stops on first failure. This is fast-fail for CI but can mask multiple issues during development. Is this intentional, or should local dev use `--maxfail=0`?

### Architecture

11. **web_api module:** `src/code_audit/web_api/` contains a FastAPI-based API with 22 endpoint tests. What is the deployment target for this? Is it part of the v1 contract surface or experimental?

12. **ML modules:** `src/code_audit/ml/` has bug prediction and clustering modules. Are these intended for production use, or are they experimental research? They are not currently covered by the contract enforcement gates.

13. **Build system:** This repo uses `setuptools` while `code-rescue-tool` uses `hatchling`. Is there a plan to standardize? Both work, but it creates cognitive overhead for cross-repo contributors.

---

## 10. Summary of What Was Shipped (Session: 2026-02-14)

| Shipment | Files Created/Modified | Commit |
|---|---|---|
| Analyzer registry contract | `test_analyzer_registry_contract.py`, `api.py` (added `RoutersAnalyzer`) | `8476a28` |
| Version bump enforcement | `test_version_bump_enforcement.py`, `scripts/refresh_logic_manifest.py`, `tests/contracts/logic_manifest.json` | `8476a28` |
| Golden manifest gate | `test_golden_manifest_requires_signal_logic_bump.py`, `scripts/refresh_golden_manifest.py`, `tests/contracts/golden_fixtures_manifest.json` | `8476a28` |
| Translator policy gate | `test_translator_policy_requires_signal_logic_bump.py`, `scripts/refresh_translator_policy_manifest.py`, `tests/contracts/translator_policy_manifest.json` | `8476a28` |
| Translator copy-key contract | `test_translator_copy_key_contract_fields.py` | `8476a28` |
| API/CLI parity | `test_api_cli_parity_ci.py`, `tests/fixtures/repos/sample_repo_exceptions/` | `8476a28` |
| EVIDENCE_* copy keys | `insights/translator.py` (8 constants added) | `8476a28` |

**Total:** 146 files changed, 27,293 insertions in commit `8476a28`.

---

## 11. Subsequent Shipments (Sessions: 2026-02-15)

| Shipment | Files Created/Modified | Commit |
|---|---|---|
| Rule registry semantic validation | `schemas/rule_registry.schema.json` (fix `\d` → `[0-9]`), refreshed logic manifest | `e5b060f` |
| Public rule buckets | `src/code_audit/rules.py` (PUBLIC/EXPERIMENTAL/DEPRECATED), schema files (`schema_version: rule_registry_v1`) | `809f235` |
| Migration script + detector + CI | `scripts/migrate_rule_ids_to_public.py`, `scripts/needs_rule_registry_migration.py`, `.github/workflows/rule-registry-sync.yml` | `722b270` |
| Schema validator + rule registry gate | `scripts/validate_rule_registry.py`, `tests/test_rule_registry_requires_signal_logic_bump.py`, `scripts/refresh_rule_registry_manifest.py` | `05a0243` |
| Reverse-direction parity + confidence gate | `tests/test_public_rules_registry_parity_contract.py`, `tests/test_confidence_policy_requires_signal_logic_bump.py`, refresh scripts | `237a812` |
| Dependency-closure hashing | Rewritten confidence test + refresh with BFS closure resolver, `CONFIDENCE_ENTRYPOINTS` override, §11 in `docs/CONTRACT.md` | `bbfe270` |
| CI enforcement guard | `_is_ci()` + `_require_entrypoints_in_ci()` in confidence test + refresh, pinned `CONFIDENCE_ENTRYPOINTS` in `pytest.yml` | `c5abd37` |
| Standalone CI env contract | `tests/test_ci_env_contracts.py` | `22efbeb` |
| Cross-repo contracts bundle | `scripts/refresh_contracts_bundle.py`, `tests/test_contracts_bundle_is_fresh.py`, `docs/contracts_bundle.json` | `22efbeb` |
| Nightly observer workflow | `.github/workflows/contract-parity-main-observer.yml` — rolling issue open/reopen/auto-close | (current) |

---

## 12. Subsequent Shipments (Session: 2026-02-16)

| Shipment | Files Created/Modified | Commit |
|---|---|---|
| Enforce unique marker insertion (Patch 13) | `.github/workflows/contract-parity-main-observer.yml` — `stripAllMarkers`, `upsertUniqueMarker`, `uniqueMarkerLines` | `677111f` |
| Tamper detection for duplicate markers (Patch 14) | Same workflow — `countMarkerOccurrences`, `assertMarkerUniqueness` on both paths | `d1cdd74` |
| Resolved comment marker uniqueness (Patch 15) | Same workflow — `assertMarkerExactlyOnce`, `assertResolvedPeriodMarkerExactlyOnce` | `cd76cff` |
| Breach comment marker uniqueness (Patch 16) | Same workflow — `assertBudgetPeriodMarkerExactlyOnce`, CI marker on breach comment | `8e140fc` |
| Canonical marker block (Patch 17) | Same workflow — `canonicalMarkerBlock`, `rewriteMarkerBlock`, `assertSingleMarkerBlock`, `assertNoStrayMarkerLinesOutsideBlock` | `82b93ef` |
| Drift budget signal promotion | `schemas/drift_budget_signal.schema.json`, `schemas/drift_budget_signal.example.json`, `scripts/generate_drift_budget_signal.py`, `scripts/validate_drift_budget_signal.py`, `scripts/refresh_drift_budget_signal_manifest.py`, `tests/contracts/drift_budget_signal_manifest.json`, `tests/test_drift_budget_signal_requires_signal_logic_bump.py`, workflow wiring | (pending) |

---

*This document was generated on 2026-02-14 and updated on 2026-02-16. It supplements (does not replace) `DEVELOPER_HANDOFF.md` (2026-02-11) and `docs/CONTRACT.md`.*
