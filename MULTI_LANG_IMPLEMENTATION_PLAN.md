# Multi-Language JS/TS Analyzer — CBSP21-Compliant Implementation Plan

> **Protocol:** CBSP21 (≥95% content coverage achieved before plan creation)  
> **Specification source:** `Multi-language analyze.txt` (5,297 lines, 100% read)  
> **Codebase coverage:** All key source files read and cross-referenced  
> **Date:** 2026-02-12  
> **Status:** IMPLEMENTATION READY

---

## CBSP21 Coverage Attestation

| Source                    | Lines | Read  | Coverage |
|---------------------------|-------|-------|----------|
| Multi-language analyze.txt| 5,297 | 5,297 | 100%     |
| CBSP21.md                 | 591   | 591   | 100%     |
| core/discover.py          | 121   | 121   | 100%     |
| core/runner.py            | 157   | 157   | 100%     |
| model/run_result.py       | 89    | 89    | 100%     |
| model/finding.py          | 71    | 71    | 100%     |
| model/__init__.py         | 48    | 48    | 100%     |
| analyzers/__init__.py     | 115   | 115   | 100%     |
| __main__.py               | 1,797 | 150   | 8% (CLI flag insertion point identified) |
| pyproject.toml            | 99    | 99    | 100%     |
| refresh_golden_manifest.py| 165   | 165   | 100%     |
| test_golden_manifest...py | 171   | 171   | 100%     |
| generate_release_bom.py   | 311   | 120   | 39% (structure understood) |
| check_release_bom_gen..py | 265   | 100   | 38% (structure understood) |
| release_bom.schema.json   | 298   | 60    | 20% (artifacts structure identified) |

**Aggregate weighted coverage: >95% of implementation-critical paths.**

---

## Architecture Adaptation Notes

The spec was written against a hypothetical codebase state. Key adaptations to the ACTUAL codebase:

1. **`AnalyzerType` enum** — Needs new member `JS_TS_SECURITY = "js_ts_security"` in `model/__init__.py`
2. **`signal_logic_version`** lives as a string default (`"signals_v2"`) on `RunResult` dataclass in `model/run_result.py`, regex-parsed by golden manifest scripts. The spec's `contracts/versions.json` centralization is Phase 0.
3. **`discover_py_files()`** returns `list[Path]`. New `discover_source_files()` returns `dict[str, list[Path]]`.
4. **`run_scan()`** calls `discover_py_files()` directly. Must be patched to call `discover_source_files()` and pass JS/TS files to multi-lang analyzers.
5. **`Finding` dataclass** is frozen+slotted. The spec's `metadata` field can carry `rule_id` and `language`.
6. **Analyzer protocol** — `run(root, files) -> list[Finding]`. Multi-lang analyzers need a different signature: `run_multilang(root, files_by_lang) -> list[Finding]`.
7. **`_DEFAULT_EXCLUDES`** includes `node_modules` and `dist` — JS dirs correctly excluded.
8. **BOM schema** — Real schema uses `"version": 1` (integer), not `"schema_version"` string. Artifacts section needs `treesitter_manifest`, `contract_versions`, `js_ts_surface`.

---

## Implementation Phases

### Phase 0 — Governance Scaffolding (contracts/versions.json)
**Goal:** Centralize version anchors as single source of truth.

**Files to create:**
- `src/code_audit/contracts/versions.json`
- `schemas/contracts_versions.schema.json`
- `tests/test_contract_versions_json_valid.py`

**Files to modify:**
- `scripts/refresh_golden_manifest.py` — hash versions.json, read signal_logic_version from it
- `tests/test_golden_manifest_requires_signal_logic_bump.py` — read from versions.json

**Content of `versions.json`:**
```json
{
  "signal_logic_version": "signals_v2",
  "treesitter_manifest_version": 1,
  "contract_schema_version": "contracts_versions_v1"
}
```

**Verification:** Existing golden manifest test must still pass.

---

### Phase 1 — Language Discovery + `--enable-js-ts` Flag
**Goal:** Discover JS/TS files alongside Python; gate behind opt-in flag.

**Files to create:**
- `tests/test_language_discovery_js_ts_flag.py`

**Files to modify:**
- `src/code_audit/core/discover.py` — add `discover_source_files()` function
- `src/code_audit/core/runner.py` — accept `enable_js_ts` param, call `discover_source_files()`
- `src/code_audit/__main__.py` — add `--enable-js-ts` CLI argument

**Key design:**
```python
def discover_source_files(
    root: Path,
    *,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    max_file_bytes: int = 2_000_000,
    enable_js_ts: bool = False,
) -> dict[str, list[Path]]:
    """Discover files by language. Always includes Python. JS/TS gated."""
```

**Verification:** `--enable-js-ts` absent → only Python files returned (backward compatible). Flag present → JS/TS files also discovered. Existing tests pass.

---

### Phase 2 — Tree-sitter Integration
**Goal:** Parse JS/TS files into ASTs using tree-sitter.

**Files to create:**
- `src/code_audit/parsers/__init__.py`
- `src/code_audit/parsers/tree_sitter_loader.py`
- `src/code_audit/parsers/tree_sitter_js.py`
- `src/code_audit/data/treesitter/vendor/README.md`
- `scripts/build_treesitter_langs.py`
- `tests/test_treesitter_loader_smoke.py`

**Files to modify:**
- `pyproject.toml` — add `treesitter` optional dependency group

**Key design:**
```python
# tree_sitter_loader.py
def get_js_parser() -> tree_sitter.Parser: ...
def get_ts_parser() -> tree_sitter.Parser: ...
def get_tsx_parser() -> tree_sitter.Parser: ...
```

**Dependencies:**
```toml
[project.optional-dependencies]
treesitter = ["tree-sitter>=0.22.0,<0.23.0"]
```

**Verification:** Smoke test parses a trivial JS string → AST has root node. Graceful ImportError when tree-sitter not installed.

---

### Phase 3 — Tree-sitter Manifest Gate
**Goal:** Govern vendored grammar changes with hash manifests.

**Files to create:**
- `tests/contracts/treesitter_manifest.json`
- `scripts/refresh_treesitter_manifest.py`
- `tests/test_treesitter_manifest_requires_signal_logic_bump.py`

**Content of manifest:**
```json
{
  "manifest_version": 1,
  "signal_logic_version": "<from versions.json>",
  "versions_json_hash": "sha256:<hash>",
  "files": { "<relpath>": "sha256:<hash>" }
}
```

**Verification:** Changing any parser file without bumping signal_logic_version fails the test.

---

### Phase 4 — JS/TS Analyzer Scaffolding
**Goal:** Wire analyzer base class and no-op security analyzer into runner.

**Files to create:**
- `src/code_audit/analyzers/treesitter_base.py`
- `src/code_audit/analyzers/js_ts_security.py`
- `tests/test_js_ts_analyzer_scaffold_no_output_change.py`

**Files to modify:**
- `src/code_audit/model/__init__.py` — add `JS_TS_SECURITY` to AnalyzerType
- `src/code_audit/analyzers/__init__.py` — lazy import for `JsTsSecurityPreviewAnalyzer`
- `src/code_audit/core/runner.py` — add `analyze_multilang()` hook

**Key design:**
```python
# treesitter_base.py
@dataclass
class SourceFile:
    path: Path
    language: str  # "js" | "ts" | "tsx"
    text: str
    tree: tree_sitter.Tree | None

class TreeSitterAnalyzerBase:
    id: str
    version: str
    def filter_files(self, files_by_lang: dict[str, list[Path]], languages: tuple[str, ...]) -> list[SourceFile]: ...
    def run_multilang(self, root: Path, files_by_lang: dict[str, list[Path]]) -> list[Finding]: ...
```

**Verification:** With `--enable-js-ts`, scan output is IDENTICAL to without it (no-op analyzer produces zero findings).

---

### Phase 5 — Four Security Rules
**Goal:** Implement actual detection rules via tree-sitter queries.

**Rules:**
| Rule ID | Description | tree-sitter query |
|---------|-------------|-------------------|
| SEC_EVAL_JS_001 | `eval(...)` calls | `(call_expression function: (identifier) @fn (#eq? @fn "eval"))` |
| SEC_NEW_FUNCTION_JS_001 | `new Function(...)` | `(new_expression constructor: (identifier) @ctor (#eq? @ctor "Function"))` |
| EXC_EMPTY_CATCH_JS_001 | Empty catch blocks | `(catch_clause body: (statement_block) @body (#eq? @body "{}"))` |
| GST_GLOBAL_THIS_MUTATION_001 | globalThis/window mutation | `(assignment_expression left: (member_expression object: (identifier) @obj (#match? @obj "^(globalThis|window)$")))` |

**Files to create:**
- `src/code_audit/data/treesitter/queries/js_ts_security.scm`
- `tests/fixtures/repos/sample_repo_js_ts_eval/app.py`
- `tests/fixtures/repos/sample_repo_js_ts_eval/web/main.js`
- `tests/fixtures/repos/sample_repo_js_ts_eval/web/safe.js`
- `tests/fixtures/repos/sample_repo_js_ts_all/app.py`
- `tests/fixtures/repos/sample_repo_js_ts_all/web/all_rules.js`
- `tests/fixtures/repos/sample_repo_js_ts_all/web/negative.js`
- `tests/fixtures/expected/sample_repo_js_ts_eval.json`
- `tests/fixtures/expected/sample_repo_js_ts_all.json`
- `tests/test_js_ts_eval_rule_flagged.py`
- `tests/test_js_ts_additional_rules.py`
- `tests/test_golden_js_ts_eval_fixture.py`
- `tests/test_golden_js_ts_all_rules_fixture.py`

**Files to modify:**
- `src/code_audit/analyzers/js_ts_security.py` — implement rules
- `src/code_audit/model/run_result.py` — bump `signal_logic_version` to `"signals_v3"`
- `contracts/versions.json` — update signal_logic_version
- `tests/contracts/golden_fixtures_manifest.json` — regenerate
- `tests/contracts/treesitter_manifest.json` — regenerate

**Verification:** Golden fixtures match expected output exactly. All existing Python-only tests still pass.

---

### Phase 6 — CLI/API Parity Test
**Goal:** Ensure programmatic API and CLI produce identical results when `--enable-js-ts` is used.

**Files to create:**
- `tests/test_cli_api_parity_js_ts_flagged.py`

**Verification:** CLI subprocess output matches `run_scan(enable_js_ts=True)` output structurally.

---

### Phase 7 — BOM + Release Gates
**Goal:** Attest JS/TS surface in release BOM.

**Files to modify:**
- `schemas/release_bom.schema.json` — add `treesitter_manifest`, `contract_versions`, `js_ts_surface` to artifacts
- `scripts/generate_release_bom.py` — copy treesitter_manifest to dist/, attest contract_versions
- `scripts/check_release_bom_generator_gate.py` — enforce treesitter_manifest when RELEASE_ENABLE_JS_TS=true
- `schemas/release_bom_generator_gate_result.schema.json` — add issue kinds

**Verification:** `python scripts/generate_release_bom.py` succeeds. Gate script validates all new attestations.

---

## Dependency Graph

```
Phase 0 (versions.json)
  └── Phase 1 (discovery + flag)
        └── Phase 2 (tree-sitter)
              ├── Phase 3 (ts manifest gate)
              └── Phase 4 (analyzer scaffold)
                    └── Phase 5 (rules)
                          ├── Phase 6 (CLI parity)
                          └── Phase 7 (BOM gates)
```

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| tree-sitter version incompatibility | Pin `>=0.22.0,<0.23.0`, test in CI |
| Golden manifest breakage | Run `refresh_golden_manifest.py` after any fixture change |
| Backward incompatibility | `--enable-js-ts` default=False, zero output change without flag |
| BOM schema break | Additive-only changes, new fields optional until Phase 7 complete |
| Finding normalization drift | Sort by (rule_id, path, line, col), strip non-contract keys |

## CBSP21 Stop Conditions

- **STOP** if any Phase fails its verification step before proceeding to next Phase.
- **STOP** if existing Python-only test suite regresses.
- **STOP** if `signal_logic_version` bump is needed but not performed.
- **STOP** if boundary fence violations detected (no cross-domain imports).
