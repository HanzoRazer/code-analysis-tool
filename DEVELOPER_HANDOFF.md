# Developer Handoff — code_audit Expansion

**Date:** 2026-02-11  
**Package:** `code_audit` (formerly `code_analysis_tool`)  
**Status:** All 348 tests passing on Python 3.13

---

## 1. Executive Summary

What started as a small **confidence-scoring engine** for beginner Vibe Coders has been rearchitected into a **full-spectrum code audit platform**. The project scope has expanded from "scan Python files and output a confidence score" to "detect, classify, govern, track, report, and predict code health issues across an entire codebase."

This document describes what changed, why, and what the current developer needs to know to continue the work.

---

## 2. Change in Direction

### Original Vision (code_analysis_tool)

The original tool had a narrow charter:

- Parse Python files with `ast`, detect basic issues (complexity, exception handling)
- Translate findings into user-facing **signals** with copy governance (i18n)
- Emit two JSON artifacts: `run_result.json` and `signals_latest.json`
- Provide a confidence score (0–100) and a tier (green / yellow / red)

It was a one-shot scanner. Run it, get a score, move on.

### New Vision (code_audit)

The expanded tool is a **continuous code health platform**:

| Capability | Original | Current |
|---|---|---|
| Scan & score | Yes | Yes (enhanced) |
| Architectural contracts | No | **Safety fences, fence registry** |
| Governance gates | No | **Deprecation tracking, import bans, legacy-usage budgets, SDK boundary enforcement** |
| Structural debt detection | No | **God Class / God Function / Deep Nesting / Feature Envy / Long Parameter List / Data Clump** |
| Debt tracking over time | No | **Snapshot registry, baseline comparison, ratchet CI gate** |
| Migration planning | No | **Auto-generated refactoring plans with priority & effort estimates** |
| Feature-flag inventory | No | **Regex-based feature hunt with custom patterns** |
| Truth-map parsing | No | **ENDPOINT_TRUTH_MAP.md parser with diff support** |
| Multi-format reporting | Score only | **Markdown, HTML (self-contained), JSON export** |
| Terminal dashboard | No | **Text-based dashboard with severity bars, hotspots, trend arrows** |
| Trend analysis | No | **Historical sparklines, direction detection (improving / worsening / stable)** |
| ML-based prediction | No | **Heuristic bug predictor, structural code clustering (stdlib k-means)** |
| CLI subcommands | 1 (`scan`) | **14 top-level subcommands (21 distinct operations)** |
| Test coverage | ~30 tests | **348 tests across 17 test files** |

| UI-facing prioritization | No | **Button subtext risk-level softening based on signal evidence** |

The key shift: **from a read-only scorer to a platform that tracks state, enforces policy, predicts risk, and drives UI decisions.**

---

## 3. Expanded Schema — Data Model

### 3.1 Original Model (2 types)

The original project had no formal model layer. Findings were plain dicts assembled inside scanner code and stuffed directly into the output JSON.

### 3.2 Current Model (5 frozen dataclasses + 6 enums + UI helpers)

All domain objects now live in `src/code_audit/model/` and are **immutable (`frozen=True, slots=True`) dataclasses** with `.to_dict()` serialization.

```
model/
├── __init__.py          # Severity, RiskLevel, Urgency, AnalyzerType enums
├── finding.py           # Location, Finding, make_fingerprint()
├── run_result.py        # RunResult (schema-aligned scan artifact)
├── debt_instance.py     # DebtType, DebtInstance, REFACTORING_STRATEGY map
└── fence.py             # FenceLevel, FenceType, FenceDefinition
```

#### Enums Added

| Enum | Values | Purpose |
|---|---|---|
| `Severity` | info, low, medium, high, critical | Finding severity tier |
| `RiskLevel` | green, yellow, red | Overall project health tier |
| `Urgency` | optional, recommended, important | Signal urgency for user-facing copy |
| `AnalyzerType` | complexity, exceptions, security, safety, global_state, dead_code | Classifier for finding source |
| `DebtType` | god_class, god_function, deep_nesting, feature_envy, long_parameter_list, data_clump | Structural debt categories |
| `FenceLevel` | info, warning, error, critical, blocker | Contract enforcement severity |
| `FenceType` | safety, import, architecture, pattern, custom | Architectural boundary kinds |

#### Finding (expanded from plain dict)

```python
@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str          # unique per run
    type: AnalyzerType       # NEW — typed enum instead of string
    severity: Severity       # NEW — typed enum
    confidence: float        # 0.0 – 1.0
    message: str
    location: Location       # NEW — structured (path, line_start, line_end)
    fingerprint: str         # SHA-256 content-addressed identity
    snippet: str             # source context
    metadata: dict           # extensible rule-specific data
```

The `fingerprint` field is the critical addition — it enables **cross-run diffing** (debt compare, ratchet gates) by producing a stable SHA-256 hash from `rule_id|path|symbol|snippet`.

#### RunResult (expanded)

```python
@dataclass(slots=True)
class RunResult:
    run_id: str
    project_id: str
    created_at: str              # ISO 8601
    tool_version: str
    engine_version: str
    signal_logic_version: str
    copy_version: str
    config: dict
    vibe_tier: RiskLevel         # was a raw string
    confidence_score: int        # 0–100
    findings: list[Finding]      # was list[dict]
    signals_snapshot: list[dict]
    snippet_policy: str
```

`to_dict()` now produces a full `run_result_v1`-compliant document with computed `summary.counts` (by_severity, by_type) generated on the fly.

#### DebtInstance (entirely new)

```python
@dataclass(frozen=True, slots=True)
class DebtInstance:
    debt_type: DebtType      # god_class, deep_nesting, etc.
    path: str
    symbol: str              # class/function name
    line_start: int
    line_end: int
    metrics: dict            # e.g. {"cc": 42, "line_count": 800}
    strategy: str            # refactoring recommendation
    fingerprint: str         # content-addressed
```

Each `DebtType` maps to a `REFACTORING_STRATEGY` string (e.g., God Class → "Extract Class / Extract Interface").

#### FenceDefinition (entirely new)

```python
@dataclass(frozen=True, slots=True)
class FenceDefinition:
    fence_id: str            # e.g. "no-eval"
    name: str
    fence_type: FenceType    # safety, import, architecture, pattern, custom
    level: FenceLevel        # info → blocker
    description: str
    enabled: bool
    config: dict             # pattern lists, thresholds, etc.
```

### 3.3 UI-Facing Prioritization Layer (new)

A new `ui/` package provides **pure functions** that translate signal evidence into UI presentation decisions — without changing any copy strings or analyzer logic.

```python
# src/code_audit/ui/button_copy.py

def choose_subtext_risk_level(signal: dict) -> Literal["green", "yellow", "red"]:
    """Decides which risk bucket to use for button subtext only."""
    # If type=exceptions and risk=red but swallowed_count == 0:
    #   → soften to yellow (less "panic-button" for beginners)
    # Otherwise: use signal.risk_level as-is

def resolve_button_subtext(buttons_i18n, *, signal, tier) -> str:
    """Look up the localized subtext string from buttons.json."""
```

**Design constraints:**
- Pure functions — no filesystem, no network, no side effects
- Does not mutate signals, findings, or copy keys
- Only affects the *subtext line under buttons*, not signal cards
- Fallback chain: requested risk → yellow → green → red → empty string

This layer is the first step toward **separation of analysis logic from presentation logic**. Future UI decisions (tooltip variants, card ordering, progressive disclosure) should follow the same pattern: pure functions that accept signal data and return presentation values.

### 3.4 JSON Schemas (unchanged externally, richer internally)

The two public schemas (`run_result.schema.json`, `signals_latest.schema.json`) are **unchanged** — backward compatibility is preserved. What changed is that the *internal* code now produces richer output:

- `findings_raw[].metadata` carries rule-specific details (file size, duplication ratio, debt type, etc.)
- `summary.counts.by_type` now has 6 analyzer type categories instead of varying strings
- Fingerprints are consistent SHA-256 hashes instead of ad-hoc identifiers

---

## 4. Expanded Scope — Module Map

### 4.1 Original Package (5 subpackages, ~8 modules)

```
code_analysis_tool/
├── cli.py                    # single entry point
├── analysis/
│   ├── discover.py           # file finder
│   ├── findings.py           # finding helpers
│   └── scanners/python_ast.py
├── contracts/load.py         # schema loading
├── pipeline/run.py, config.py
└── signals/engine.py         # signal translation
```

### 4.2 Current Package (12 subpackages, 30+ modules)

```
code_audit/
├── __main__.py               # 1420-line CLI with 14 subcommands (21 operations)
│
├── model/                    # ★ NEW — formal domain model
│   ├── finding.py, run_result.py, debt_instance.py, fence.py
│
├── core/                     # refactored from pipeline/
│   ├── runner.py, discover.py, config.py
│
├── analyzers/                # ★ EXPANDED — 4 analyzers (was 1)
│   ├── complexity.py         # cyclomatic complexity
│   ├── exceptions.py         # bare except, broad except, swallowed errors
│   ├── duplication.py        # structural code clones (AST-based)
│   └── file_sizes.py         # oversized file detection
│
├── insights/                 # refactored from signals/
│   ├── confidence.py         # score computation
│   └── translator.py         # finding → signal
│
├── contracts/                # ★ EXPANDED — safety boundaries
│   ├── safety_fence.py       # pattern-based fence checks
│   ├── fence_registry.py     # built-in fence catalog
│   └── load.py
│
├── governance/               # ★ NEW — policy enforcement
│   ├── deprecation.py        # sunset-date tracking with registries
│   ├── import_ban.py         # banned import pattern detection
│   ├── legacy_usage.py       # legacy route budget enforcement
│   └── sdk_boundary.py       # frontend SDK bypass detection
│
├── strangler/                # ★ NEW — debt lifecycle
│   ├── debt_detector.py      # 6 structural debt patterns
│   ├── plan_generator.py     # prioritized refactoring plans
│   └── debt_registry.py      # snapshot save/load/compare + ratchet
│
├── reports/                  # ★ NEW — multi-format output
│   ├── debt_report.py        # Markdown debt report with git info
│   ├── exporters.py          # JSON / Markdown / HTML export
│   ├── dashboard.py          # terminal-friendly text dashboard
│   └── trend_analysis.py     # historical trend with sparklines
│
├── inventory/                # ★ NEW — codebase inventory
│   └── feature_hunt.py       # feature-flag regex scanner
│
├── ml/                       # ★ NEW — experimental ML
│   ├── feature_extraction.py # 8-dimension feature vectors from AST
│   ├── bug_predictor.py      # heuristic bug probability scoring
│   └── code_clustering.py    # stdlib k-means file grouping
│
├── ui/                       # ★ NEW — UI-facing presentation logic
│   ├── __init__.py           # pure functions only (no I/O)
│   └── button_copy.py        # subtext risk-level softening
│
└── utils/                    # ★ NEW — shared utilities
    └── parse_truth_map.py    # ENDPOINT_TRUTH_MAP.md parser
```

---

## 5. CLI Expansion

### Original: 2 commands

```
code-analysis-tool <path>
code-analysis-tool scan --root <dir> --out <dir>
```

### Current: 17 subcommands

| Command | Phase | Purpose |
|---|---|---|
| `<path>` | P1 | Default scan with class-based pipeline |
| `scan` | P1 | Functional pipeline scan with JSON output |
| `validate` | P1 | Validate JSON against schemas |
| `fence check` | P2 | Check safety fences (eval, exec, pickle, etc.) |
| `fence list` | P2 | List all registered fences |
| `governance deprecation` | P3 | Check for deprecated API usage |
| `governance import-ban` | P3 | Enforce import bans |
| `governance legacy-usage` | P3 | Track legacy route usage budgets |
| `report` | P4 | Generate Markdown debt report |
| `debt scan` | P5 | Detect structural tech debt |
| `debt plan` | P5 | Generate refactoring plan |
| `debt snapshot` | P5 | Save named debt snapshot |
| `debt compare` | P5 | Compare current debt vs baseline |
| `inventory` | P6 | Hunt for feature flags |
| `sdk-boundary` | P6 | Detect SDK boundary violations |
| `truth-map` | P6 | Parse endpoint truth maps |
| `trend` | P7 | Historical debt trend analysis |
| `export` | P7 | Export scan results (JSON/MD/HTML) |
| `dashboard` | P7 | Terminal health dashboard |
| `predict` | P7 | ML bug probability prediction |
| `cluster` | P7 | K-means file clustering |

14 top-level subcommands; `debt`, `fence`, and `governance` have nested sub-subcommands for 21 distinct operations total. All support `--json` where applicable and write to stdout by default (CI-friendly).

---

## 6. Test Expansion

| Test File | Test Count | Covers |
|---|---|---|
| `test_cbsp21_schema.py` | 2 | CBSP21 patch input schema validation |
| `test_copy_lint_smoke.py` | 1 | i18n copy lint smoke |
| `test_copy_lint_vibe_saas.py` | 4 | Copy lint Vibe SaaS rules |
| `test_data_model_schemas.py` | 17 | Schema validation for all JSON schemas |
| `test_golden_fixtures.py` | 14 | Golden output regression |
| `test_run_result_schema.py` | 2 | RunResult schema compliance |
| `test_exceptions_analyzer_pipeline.py` | 4 | Exception analyzer integration + UI subtext |
| `test_scan_pipeline.py` | 8 | Full scan pipeline integration |
| `test_file_sizes.py` | 12 | File size analyzer unit tests |
| `test_duplication.py` | 14 | Duplication analyzer unit tests |
| `test_safety_fence.py` | 23 | Safety fence + registry tests |
| `test_governance.py` | 42 | Deprecation, import-ban, legacy-usage tests |
| `test_debt_report.py` | 25 | Debt report generation tests |
| `test_strangler.py` | 40 | Debt detector, plan generator, registry tests |
| `test_supporting_modules.py` | 57 | Feature hunt, SDK boundary, truth map tests |
| `test_phase7.py` | 81 | Trend, exporters, dashboard, ML modules, CLI |
| `test_ui_button_subtext_prioritization.py` | 2 | UI subtext risk-level softening |
| **Total** | **348** | |

Original test count: ~30. Current: **348** (11.6x increase).

Note: `test_exceptions_analyzer_pipeline.py` was expanded from 3 → 4 tests to include a UI integration test verifying that button subtext resolves correctly for exception signals with swallowed errors.

---

## 7. Architectural Decisions

### 7.1 Zero External Dependencies (runtime)

Every module — including the ML layer — uses **only the Python stdlib**. The k-means implementation uses `random` + `math`. Feature extraction uses `ast`. No numpy, sklearn, pandas, etc.

**Rationale:** The tool runs in CI where pip installs should be minimal. Dev dependencies (pytest, jsonschema, ruff) are optional.

**Future migration path:** The `BugPredictor` and `CodeClusterer` classes have stable public APIs. Swap their internals for sklearn equivalents when training data is available. No consumer code changes needed.

### 7.2 Frozen Dataclasses Everywhere

All model objects use `@dataclass(frozen=True, slots=True)`. This guarantees:

- Thread safety (immutable state)
- Hashability (can be used in sets, dict keys)
- Memory efficiency (slots)
- No accidental mutation bugs

`RunResult` is the one exception — it uses `slots=True` but not `frozen=True` because it accumulates findings during a scan run.

### 7.3 Content-Addressed Fingerprints

Findings and debt instances use SHA-256 fingerprints derived from `rule_id|path|symbol|snippet`. This enables:

- Cross-run diffing (`debt compare`)
- Ratchet CI gates (exit 1 if new debt introduced)
- Deduplication across analyzers

### 7.4 Analyzer Protocol

All analyzers follow a consistent protocol:

```python
class SomeAnalyzer:
    id: str            # unique identifier
    version: str       # semver
    
    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        ...
```

This makes it trivial to add new analyzers — implement `run()`, wire into `__main__.py`, done.

### 7.5 Presentation / Analysis Separation

The `ui/` package establishes a clear boundary: **analyzers produce data, UI helpers interpret it for presentation**. Key rules:

- UI functions receive signal dicts, never raw AST nodes or file paths
- UI functions never mutate their inputs
- UI functions never import from `analyzers/`, `core/`, or `strangler/`
- Copy strings live in `i18n/`, not in Python code

This makes it safe to change presentation logic without risk of breaking analysis, and vice versa.

### 7.6 Package Rename

The package was renamed from `code_analysis_tool` to `code_audit` during the port. The entry point changed from `code-analysis-tool` to `code-audit`. The `pyproject.toml` `[project.scripts]` reflects this.

---

## 8. Known Limitations & Future Work

| Area | Status | Next Steps |
|---|---|---|
| ML models | Heuristic-only | Train logistic regression / random forest on real bug data |
| HTML dashboard | Static export | Add live auto-refresh (WebSocket or polling) |
| Trend analysis | File-based snapshots | Add database backend for large-scale history |
| Language support | Python-only (`ast`) | Extend to JS/TS via tree-sitter or similar |
| parallelism | Sequential scans | Add `concurrent.futures` for large codebases |
| Config file | CLI flags only | Support `.code-audit.toml` config files |
| Fence definitions | Hardcoded registry | Load from YAML/JSON config files |
| SDK boundary | Regex-based | Integrate with OpenAPI specs for precision |
| UI logic | Subtext only | Expand to tooltip variants, card ordering, progressive disclosure |

---

## 9. How to Continue

### Running Tests

```bash
python -m pytest tests/ -v          # all 348 tests
python -m pytest tests/ -k "phase7" # just Phase 7
```

### Adding a New Analyzer

1. Create `src/code_audit/analyzers/your_analyzer.py`
2. Implement the `run(root, files) -> list[Finding]` protocol
3. Add it to the default analyzer list in `__main__.py` (around line 1380)
4. Write tests in `tests/test_your_analyzer.py`

### Adding a New CLI Subcommand

1. Add parser definition in `_build_parser()` (follow existing pattern with unique dest prefixes)
2. Add handler function `_handle_your_command(args)`
3. Add dispatch entry in `main()`
4. Update the docstring at the top of `__main__.py`

### Key Files to Read First

- [src/code_audit/model/](src/code_audit/model/) — understand the domain model
- [src/code_audit/__main__.py](src/code_audit/__main__.py) — understand the CLI surface
- [src/code_audit/core/runner.py](src/code_audit/core/runner.py) — understand the scan pipeline
- [tests/test_phase7.py](tests/test_phase7.py) — the most recent test patterns

---

## 10. Phase History

| Phase | Weeks | Deliverables | Tests Added |
|---|---|---|---|
| P1 — Core Analyzers | 1-2 | complexity, duplication, exceptions, file_sizes analyzers; model layer; core runner | ~50 |
| P2 — Safety Contracts | 3-4 | safety_fence, fence_registry | 23 |
| P3 — Governance Gates | 5-6 | deprecation, import_ban, legacy_usage | 42 |
| P4 — Reporting | 7-8 | debt_report (Markdown) | 25 |
| P5 — Strangler Fig | 9-10 | debt_detector, plan_generator, debt_registry | 40 |
| P6 — Supporting Modules | 11-12 | feature_hunt, sdk_boundary, parse_truth_map | 57 |
| P7 — Reports & ML | 13-14 | trend_analysis, exporters, dashboard, feature_extraction, bug_predictor, code_clustering | 81 |
| UI Layer | — | ui/button_copy (subtext risk-level softening) | 3 |
| **Total** | | **30+ modules, 13 subpackages, 14 CLI subcommands (21 ops)** | **348** |
