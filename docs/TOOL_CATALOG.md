# Code Analysis Tool Catalog

Source: `luthiers-toolbox/services/api/app/ci/`

This document catalogs all analysis tools available for porting, organized by category with deployment recommendations.

---

## Category 1: Code Quality Analyzers

### 1.1 check_complexity.py
**Purpose:** Cyclomatic complexity gate using radon library

**What it does:**
- Scans all Python files for functions exceeding complexity threshold (default: 15)
- Uses radon library to calculate McCabe cyclomatic complexity
- Grades functions A-F based on complexity score
- Supports baseline mode (ratchet) to only fail on NEW violations

**CLI:**
```bash
python -m check_complexity [--threshold N] [--baseline FILE] [--write-baseline] [--json]
```

**Exit codes:** 0=OK, 1=violations, 2=error

**Dependencies:** `radon`

**Deployment category:** `analyzers/complexity.py` (already exists in code-analysis-tool)

---

### 1.2 check_file_sizes.py
**Purpose:** Large file detector

**What it does:**
- Scans all Python files for those exceeding line count threshold (default: 500)
- Flags files that need splitting/refactoring
- Supports baseline mode for existing large files

**CLI:**
```bash
python -m check_file_sizes [--threshold N] [--baseline FILE] [--write-baseline] [--json]
```

**Exit codes:** 0=OK, 1=violations, 2=error

**Dependencies:** None (stdlib only)

**Deployment category:** `analyzers/file_sizes.py`

---

### 1.3 check_duplication.py
**Purpose:** AST-based code duplication detector

**What it does:**
- Finds duplicate code blocks using structural AST hashing
- Groups duplicate functions/classes by hash
- Lighter than jscpd, no npm required
- Reports clone groups and total duplicate lines

**CLI:**
```bash
python -m check_duplication [--threshold N] [--min-lines N] [--json] [--top N]
```

**Exit codes:** 0=OK, 1=threshold exceeded, 2=error

**Dependencies:** None (stdlib only)

**Deployment category:** `analyzers/duplication.py`

---

### 1.4 check_bare_except.py
**Purpose:** Bare except clause detector

**What it does:**
- AST scan for `except:` clauses without specific exception types
- Bare excepts hide bugs and make debugging difficult
- Critical for safety-critical code

**CLI:**
```bash
python -m check_bare_except [--json]
```

**Exit codes:** 0=OK, 1=violations found

**Dependencies:** None (stdlib only)

**Deployment category:** `analyzers/exceptions.py` (already exists)

---

### 1.5 vue_component.py
**Purpose:** Vue SFC god object detector

**What it does:**
- Parses Vue Single File Components (.vue files)
- Detects components exceeding LOC thresholds (500/800/1500)
- Identifies extractable template sections via HTML comment markers
- Detects script-heavy components needing composable extraction
- Calculates template/script ratios
- Counts child components, composables, props, emits

**Rule IDs:**
- `VUE-GOD-001` (MEDIUM): Component exceeds 500 LOC
- `VUE-GOD-002` (HIGH): Component exceeds 800 LOC (god object)
- `VUE-GOD-003` (CRITICAL): Component exceeds 1500 LOC
- `VUE-EXTRACT-001` (LOW): Template section extractable as child component
- `VUE-COMPOSABLE-001` (MEDIUM): Script-heavy, needs composable extraction

**Usage:**
```python
from code_audit.analyzers import VueComponentAnalyzer

analyzer = VueComponentAnalyzer(threshold=500, high_threshold=800)
findings = analyzer.run(root_path, vue_files)
```

**Dependencies:** None (stdlib only)

**Deployment category:** `analyzers/vue_component.py`

**Cross-repo:** Findings consumed by `code-rescue-tool` `VueComponentFixer` for extraction scaffolds.

---

## Category 2: Safety & Contract Validators

### 2.1 fence_checker_v2.py
**Purpose:** Safety fence validator for code contracts

**What it does:**
- Checks for bare except clauses (ERROR severity)
- Checks for missing @safety_critical decorators on safety functions
- Functions matching patterns: `generate_gcode`, `calculate_feeds`, `compute_feasibility`, `validate_toolpath`
- Excludes Protocol files and `_hash`/`_stub` suffix functions

**CLI:**
```bash
python -m fence_checker_v2 [--strict] [--json]
```

**Exit codes:** 0=OK, 2=ERROR, 3=CRITICAL, 4=BLOCKER

**Dependencies:** None (stdlib only)

**Deployment category:** `contracts/safety_fence.py`

---

### 2.2 fence_runner.py
**Purpose:** Registry-driven architectural boundary enforcement

**What it does:**
- Reads FENCE_REGISTRY.json for fence definitions
- Executes enabled fence checks (forbidden imports, domain rules, patterns)
- Supports dry-run mode and individual profile selection

**CLI:**
```bash
python -m fence_runner                    # Run all enabled fences
python -m fence_runner --profile NAME     # Run specific fence
python -m fence_runner --list             # List all fences
python -m fence_runner --dry-run          # Show what would run
```

**Exit codes:** 0=OK, 1=violations found

**Dependencies:** FENCE_REGISTRY.json config file

**Deployment category:** `contracts/fence_runner.py`

---

### 2.3 check_all_fences.py
**Purpose:** Umbrella runner for all fence checks

**What it does:**
- Single entry point for all boundary fence checks
- Runs both import-based and pattern-based fence checks
- Supports baseline/ratchet mode

**CLI:**
```bash
python -m check_all_fences              # Baseline mode (default)
python -m check_all_fences --strict     # Strict mode (no baselines)
python -m check_all_fences --write-baselines  # Regenerate baselines
```

**Dependencies:** check_boundary_imports.py, check_boundary_patterns.py

**Deployment category:** `contracts/all_fences.py`

---

## Category 3: API & Endpoint Validators

### 3.1 endpoint_truth_gate.py
**Purpose:** Validates actual endpoints match declared endpoint map

**What it does:**
- Parses ENDPOINT_TRUTH_MAP.md (canonical source)
- Introspects FastAPI app routes
- Reports missing and unexpected endpoints
- Enforces endpoint governance

**CLI:**
```bash
python -m endpoint_truth_gate check
```

**Config env:**
- `ENDPOINT_TRUTH_MAP_PATH` - Path to truth map markdown
- `ENDPOINT_TRUTH_EXTRA_ALLOWLIST` - Comma-separated METHOD:PATH exceptions

**Exit codes:** 0=OK, 1=mismatch, 2=config error

**Dependencies:** FastAPI app module

**Deployment category:** `contracts/endpoint_truth.py`

---

### 3.2 inventory_endpoints.py
**Purpose:** Generate endpoint inventory from FastAPI app

**What it does:**
- Introspects FastAPI OpenAPI spec
- Outputs JSON inventory of all endpoints
- Useful for documentation and audit

**CLI:**
```bash
python -m inventory_endpoints > endpoints.json
python -m inventory_endpoints --out /path/file.json
```

**Dependencies:** FastAPI app module

**Deployment category:** `inventory/endpoints.py`

---

## Category 4: Migration & Deprecation Gates

### 4.1 check_deprecation_sunset.py
**Purpose:** Enforces deprecated code removal deadlines

**What it does:**
- Reads deprecation_registry.json with sunset dates
- Checks if module files still exist past their sunset date
- Self-executing removal: CI fails if deprecated code not removed

**CLI:**
```bash
python -m check_deprecation_sunset              # Normal mode
python -m check_deprecation_sunset --warn-only  # Warning mode
python -m check_deprecation_sunset --upcoming 30  # Warn about routes sunsetting in 30 days
```

**Exit codes:** 0=OK, 1=overdue sunsets, 2=config error

**Dependencies:** deprecation_registry.json

**Deployment category:** `governance/deprecation_sunset.py`

---

### 4.2 legacy_usage_gate.py
**Purpose:** Detect frontend usage of legacy API endpoints

**What it does:**
- Scans frontend code (TS/JS/Vue) for API path strings
- Matches against legacy route patterns
- Reports usage and suggests canonical replacements
- Budget mode allows gradual migration

**CLI:**
```bash
python -m legacy_usage_gate [--fail-on-any] [--budget N] [--json]
```

**Exit codes:** 0=no legacy, 1=under budget, 2=over budget

**Dependencies:** None (stdlib only)

**Deployment category:** `governance/legacy_usage.py`

---

### 4.3 ban_experimental_ai_core_imports.py
**Purpose:** Debt lock for deprecated module paths

**What it does:**
- Scans Python files for imports from `app._experimental.ai_core`
- Enforces migration to canonical import paths
- Skips the shim files themselves

**CLI:**
```bash
python -m ban_experimental_ai_core_imports
```

**Exit codes:** 0=OK, 2=violations found

**Dependencies:** None (stdlib only)

**Deployment category:** `governance/import_ban.py`

---

## Category 5: Reporting & Orchestration

### 5.1 generate_debt_report.py
**Purpose:** Consolidated technical debt markdown report

**What it does:**
- Runs all debt checks (complexity, file size, bare except, fences, duplication)
- Produces unified markdown report with summary table
- Includes git commit/branch info
- Suitable for GitHub artifacts or PR comments

**CLI:**
```bash
python -m generate_debt_report [--output FILE]
```

**Output:** Markdown report

**Dependencies:** All other check modules

**Deployment category:** `reports/debt_report.py`

---

## Category 6: Supporting Modules

### 6.1 feature_hunt.py / feature_hunt_types.py
**Purpose:** Feature flag detection

**What it does:**
- Searches for feature flag usage patterns
- Tracks feature adoption/removal

**Deployment category:** `inventory/feature_hunt.py`

---

### 6.2 scan_frontend_api_usage.py
**Purpose:** SDK boundary violation scanner

**What it does:**
- Finds frontend code bypassing SDK layer
- Enforces frontend → SDK → API architecture

**Deployment category:** `governance/sdk_boundary.py`

---

### 6.3 parse_truth_map.py
**Purpose:** Helper for parsing endpoint truth maps

**Deployment category:** `utils/parse_truth_map.py`

---

## Baseline Files (Data)

| File | Purpose |
|------|---------|
| `complexity_baseline.json` | Baselined complexity violations |
| `file_sizes_baseline.json` | Baselined large files |
| `fence_baseline.json` | Import boundary violations |
| `fence_patterns_baseline.json` | Pattern boundary violations |
| `deprecation_registry.json` | Deprecated code with sunset dates |

---

## Recommended Deployment Structure

```
code-analysis-tool/
├── src/code_audit/
│   ├── analyzers/           # Category 1: Code Quality
│   │   ├── complexity.py
│   │   ├── file_sizes.py
│   │   ├── duplication.py
│   │   ├── exceptions.py
│   │   └── vue_component.py  # Vue SFC god object detection
│   │
│   ├── contracts/           # Category 2: Safety & Contracts
│   │   ├── safety_fence.py
│   │   ├── fence_runner.py
│   │   ├── all_fences.py
│   │   └── endpoint_truth.py
│   │
│   ├── governance/          # Category 4: Migration Gates
│   │   ├── deprecation_sunset.py
│   │   ├── legacy_usage.py
│   │   ├── import_ban.py
│   │   └── sdk_boundary.py
│   │
│   ├── inventory/           # Category 3 & 6: Inventory
│   │   ├── endpoints.py
│   │   └── feature_hunt.py
│   │
│   ├── reports/             # Category 5: Reporting
│   │   └── debt_report.py
│   │
│   ├── utils/               # Shared utilities
│   │   └── parse_truth_map.py
│   │
│   └── data/                # Baseline files
│       ├── complexity_baseline.json
│       ├── file_sizes_baseline.json
│       └── deprecation_registry.json
│
├── schemas/                 # JSON schemas for validation
│   └── fence_registry.schema.json
│
└── tests/
    └── ...
```

---

## Execution Priority

For initial deployment, implement in this order:

1. **Core Analyzers** (no external deps)
   - `exceptions.py` (bare except)
   - `file_sizes.py`
   - `duplication.py`
   - `complexity.py` (requires radon)

2. **Safety Contracts**
   - `safety_fence.py`

3. **Governance Gates**
   - `import_ban.py`
   - `deprecation_sunset.py`

4. **Reporting**
   - `debt_report.py`

5. **Advanced (requires app introspection)**
   - `endpoint_truth.py`
   - `endpoints.py`
   - `legacy_usage.py`
