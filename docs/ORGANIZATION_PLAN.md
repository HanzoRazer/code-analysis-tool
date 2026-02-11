# Code Analysis Tool Organization Plan

Based on the luthiers-toolbox design review and Fig Strangler methodology.

---

## Source Material Summary

The source document describes a comprehensive technical debt detection and remediation system with:

1. **Design Review Framework** - Scoring system (purpose clarity, reliability, safety, etc.)
2. **Static Analysis Tools** - Complexity, duplication, exception handling
3. **Dynamic Analysis Tools** - Runtime tracing, memory analysis, concurrency
4. **Architectural Analysis** - Dependency graphs, layer boundaries, circular deps
5. **Historical Analysis** - Git history, churn, bus factor
6. **Machine Learning Approaches** - Bug prediction, code clustering
7. **Fig Strangler Pattern** - Incremental debt elimination
8. **Fence Checker System** - Contract validation between policy and implementation

---

## Proposed Repository Structure

```
code-analysis-tool/
├── src/code_audit/
│   │
│   ├── analyzers/                 # Category 1: Code Quality Analyzers
│   │   ├── __init__.py
│   │   ├── complexity.py          # Cyclomatic complexity (EXISTS)
│   │   ├── exceptions.py          # Bare/broad except (EXISTS)
│   │   ├── file_sizes.py          # Large file detection (PORT)
│   │   ├── duplication.py         # AST-based clone detection (PORT)
│   │   ├── god_objects.py         # God class/function detection (NEW)
│   │   ├── message_chains.py      # Law of Demeter violations (NEW)
│   │   └── switch_statements.py   # If-else chain detection (NEW)
│   │
│   ├── contracts/                 # Category 2: Contract Validation
│   │   ├── __init__.py            # (EXISTS)
│   │   ├── load.py                # Schema validation (EXISTS)
│   │   ├── fence_checker.py       # Main fence engine (PORT)
│   │   ├── fence_registry.py      # Fence definition storage (NEW)
│   │   ├── api_fences.py          # API contract validation (NEW)
│   │   ├── safety_fences.py       # Safety-critical validation (NEW)
│   │   └── arch_fences.py         # Architecture boundary validation (NEW)
│   │
│   ├── governance/                # Category 3: Migration & Deprecation
│   │   ├── __init__.py
│   │   ├── deprecation_sunset.py  # Sunset date enforcement (PORT)
│   │   ├── legacy_usage.py        # Legacy API detection (PORT)
│   │   ├── import_ban.py          # Forbidden import patterns (PORT)
│   │   └── sdk_boundary.py        # SDK usage enforcement (PORT)
│   │
│   ├── architecture/              # Category 4: Architectural Analysis
│   │   ├── __init__.py
│   │   ├── dependency_graph.py    # Module dependency analysis (NEW)
│   │   ├── layer_boundaries.py    # Layer violation detection (NEW)
│   │   ├── circular_deps.py       # Circular dependency detection (NEW)
│   │   └── impact_analysis.py     # Change impact prediction (NEW)
│   │
│   ├── history/                   # Category 5: Git History Analysis
│   │   ├── __init__.py
│   │   ├── churn_analysis.py      # High-churn file detection (NEW)
│   │   ├── bus_factor.py          # Knowledge concentration (NEW)
│   │   ├── commit_patterns.py     # Commit pattern analysis (NEW)
│   │   └── refactoring_detector.py # Refactoring commit detection (NEW)
│   │
│   ├── runtime/                   # Category 6: Dynamic Analysis
│   │   ├── __init__.py
│   │   ├── execution_tracer.py    # Function call tracing (NEW)
│   │   ├── memory_analyzer.py     # Memory leak detection (NEW)
│   │   ├── concurrency.py         # Race condition detection (NEW)
│   │   └── performance.py         # Performance hotspot detection (NEW)
│   │
│   ├── strangler/                 # Category 7: Fig Strangler Pattern
│   │   ├── __init__.py
│   │   ├── debt_detector.py       # Technical debt detection (NEW)
│   │   ├── debt_registry.py       # Debt instance storage (NEW)
│   │   ├── plan_generator.py      # Strangulation plan creation (NEW)
│   │   ├── facade_templates.py    # Refactoring templates (NEW)
│   │   └── progress_tracker.py    # Migration progress (NEW)
│   │
│   ├── inventory/                 # Category 8: Codebase Inventory
│   │   ├── __init__.py
│   │   ├── endpoints.py           # API endpoint inventory (PORT)
│   │   ├── feature_hunt.py        # Feature flag detection (PORT)
│   │   ├── route_classifier.py    # Route classification (NEW)
│   │   └── module_map.py          # Module/class inventory (NEW)
│   │
│   ├── reports/                   # Category 9: Reporting
│   │   ├── __init__.py
│   │   ├── debt_report.py         # Consolidated debt report (PORT)
│   │   ├── trend_analysis.py      # Historical trend reports (NEW)
│   │   ├── dashboard.py           # Interactive dashboard (NEW)
│   │   └── exporters.py           # JSON/Markdown/HTML export (NEW)
│   │
│   ├── ml/                        # Category 10: ML-Based Analysis
│   │   ├── __init__.py
│   │   ├── bug_predictor.py       # Bug probability prediction (NEW)
│   │   ├── code_clustering.py     # Similar code clustering (NEW)
│   │   └── feature_extraction.py  # Feature extraction for ML (NEW)
│   │
│   ├── core/                      # Core Infrastructure
│   │   ├── __init__.py            # (EXISTS)
│   │   ├── config.py              # (EXISTS)
│   │   ├── discover.py            # (EXISTS)
│   │   ├── runner.py              # (EXISTS)
│   │   └── baseline.py            # Baseline/ratchet support (NEW)
│   │
│   ├── model/                     # Data Models
│   │   ├── __init__.py            # (EXISTS)
│   │   ├── finding.py             # (EXISTS)
│   │   ├── run_result.py          # (EXISTS)
│   │   ├── debt_instance.py       # Technical debt model (NEW)
│   │   ├── fence.py               # Fence/contract model (NEW)
│   │   └── strangler_plan.py      # Migration plan model (NEW)
│   │
│   ├── insights/                  # Analysis Insights
│   │   ├── __init__.py            # (EXISTS)
│   │   ├── confidence.py          # (EXISTS)
│   │   ├── translator.py          # (EXISTS)
│   │   └── prioritizer.py         # Issue prioritization (NEW)
│   │
│   └── data/                      # Data Files
│       ├── schemas/               # JSON schemas
│       ├── baselines/             # Baseline snapshots
│       ├── patterns/              # Refactoring patterns
│       └── fences/                # Fence definitions
│
├── schemas/                       # Public JSON Schemas
│   ├── run_result.schema.json     # (EXISTS)
│   ├── signals_latest.schema.json # (EXISTS)
│   ├── debt_instance.schema.json  # (NEW)
│   ├── fence.schema.json          # (NEW)
│   ├── strangler_plan.schema.json # (NEW)
│   └── baseline.schema.json       # (NEW)
│
├── tests/
│   ├── fixtures/
│   ├── test_analyzers/
│   ├── test_contracts/
│   ├── test_governance/
│   ├── test_architecture/
│   ├── test_strangler/
│   └── test_reports/
│
├── scripts/
│   ├── generate_baseline.py       # Create baseline snapshot
│   ├── migrate_from_ltb.py        # Migrate from luthiers-toolbox
│   └── run_full_analysis.py       # Complete analysis pipeline
│
└── docs/
    ├── TOOL_CATALOG.md            # (EXISTS)
    ├── DEPLOYMENT_PLAN.md         # (EXISTS)
    ├── ORGANIZATION_PLAN.md       # (THIS FILE)
    ├── FENCE_ARCHITECTURE.md      # Fence system documentation
    ├── STRANGLER_PATTERN.md       # Fig Strangler methodology
    └── SCORING_RUBRIC.md          # Design review scoring criteria
```

---

## Tool Classification by Source

### From luthiers-toolbox (PORT)
| Tool | Source | Target |
|------|--------|--------|
| check_complexity.py | app/ci/ | analyzers/complexity.py |
| check_file_sizes.py | app/ci/ | analyzers/file_sizes.py |
| check_duplication.py | app/ci/ | analyzers/duplication.py |
| check_bare_except.py | app/ci/ | analyzers/exceptions.py |
| fence_checker_v2.py | app/ci/ | contracts/fence_checker.py |
| check_deprecation_sunset.py | app/ci/ | governance/deprecation_sunset.py |
| legacy_usage_gate.py | app/ci/ | governance/legacy_usage.py |
| ban_experimental_ai_core_imports.py | app/ci/ | governance/import_ban.py |
| generate_debt_report.py | app/ci/ | reports/debt_report.py |
| inventory_endpoints.py | app/ci/ | inventory/endpoints.py |

### From Design Review Document (NEW)
| Concept | Implementation | Priority |
|---------|----------------|----------|
| Fig Strangler Pattern | strangler/ module | P1 |
| Debt Detection | strangler/debt_detector.py | P1 |
| Dependency Graph | architecture/dependency_graph.py | P1 |
| Git History Analysis | history/ module | P2 |
| Runtime Tracing | runtime/ module | P3 |
| ML Bug Prediction | ml/ module | P4 |

---

## Implementation Phases

### Phase 1: Core Analyzers (Week 1-2)
**Goal:** Port and integrate existing luthiers-toolbox tools

```
Priority 1.1: Port analyzers
- [ ] file_sizes.py (adapt to Analyzer protocol)
- [ ] duplication.py (adapt to Analyzer protocol)
- [ ] Integrate with existing complexity.py and exceptions.py

Priority 1.2: Add baseline support
- [ ] Create baseline.py in core/
- [ ] Add --baseline, --write-baseline to CLI
- [ ] Create baseline.schema.json
```

### Phase 2: Fence Checker System (Week 3-4)
**Goal:** Implement contract validation framework

```
Priority 2.1: Core fence infrastructure
- [ ] fence.py model
- [ ] fence_registry.py
- [ ] fence_checker.py main engine

Priority 2.2: Fence types
- [ ] api_fences.py
- [ ] safety_fences.py
- [ ] arch_fences.py

Priority 2.3: CLI integration
- [ ] Add 'fence' subcommand
- [ ] fence check, fence list, fence init
```

### Phase 3: Governance Gates (Week 5-6)
**Goal:** Migration and deprecation enforcement

```
Priority 3.1: Port governance tools
- [ ] deprecation_sunset.py
- [ ] legacy_usage.py
- [ ] import_ban.py

Priority 3.2: Configuration
- [ ] Create governance config schemas
- [ ] Add deprecation_registry.json support
```

### Phase 4: Fig Strangler Module (Week 7-8)
**Goal:** Systematic debt elimination framework

```
Priority 4.1: Debt detection
- [ ] debt_instance.py model
- [ ] debt_detector.py (AST-based detection)
- [ ] DebtType enum (God Class, God Function, etc.)

Priority 4.2: Plan generation
- [ ] strangler_plan.py model
- [ ] plan_generator.py
- [ ] facade_templates.py

Priority 4.3: Progress tracking
- [ ] debt_registry.py
- [ ] progress_tracker.py
```

### Phase 5: Architecture Analysis (Week 9-10)
**Goal:** Dependency and layer analysis

```
Priority 5.1: Dependency graph
- [ ] dependency_graph.py (networkx-based)
- [ ] circular_deps.py
- [ ] impact_analysis.py

Priority 5.2: Layer boundaries
- [ ] layer_boundaries.py
- [ ] Configurable layer definitions
```

### Phase 6: Historical Analysis (Week 11-12)
**Goal:** Git history insights

```
Priority 6.1: Git analysis
- [ ] churn_analysis.py
- [ ] bus_factor.py
- [ ] commit_patterns.py
- [ ] refactoring_detector.py
```

### Phase 7: Reporting & Dashboard (Week 13-14)
**Goal:** Comprehensive reporting

```
Priority 7.1: Reports
- [ ] Port debt_report.py
- [ ] trend_analysis.py
- [ ] Add markdown, JSON, HTML exporters

Priority 7.2: Dashboard (optional)
- [ ] Interactive Dash/Plotly dashboard
- [ ] Visualization of debt trends
```

---

## CLI Command Structure

```bash
# Core analysis
code-audit scan [PATH]                    # Full scan
code-audit validate [FILE]                # Validate against schema

# Analyzer commands
code-audit analyze complexity [PATH]
code-audit analyze file-sizes [PATH] --threshold 500
code-audit analyze duplication [PATH]
code-audit analyze exceptions [PATH]
code-audit analyze all [PATH]             # Run all analyzers

# Fence/Contract commands
code-audit fence check [PATH]             # Run all fence checks
code-audit fence list                     # List registered fences
code-audit fence init                     # Initialize fence definitions
code-audit fence verify [FENCE_ID]        # Check specific fence

# Governance commands
code-audit deprecation check [--warn-only]
code-audit legacy-usage [--budget N]
code-audit import-ban [--patterns FILE]

# Architecture commands
code-audit deps graph [PATH]              # Generate dependency graph
code-audit deps cycles [PATH]             # Find circular dependencies
code-audit deps impact [FILE]             # Analyze change impact

# Fig Strangler commands
code-audit debt scan [PATH]               # Scan for technical debt
code-audit debt plan [DEBT_ID]            # Generate strangulation plan
code-audit debt track [PATH]              # Track debt over time
code-audit debt report [--format md|json|html]

# History commands
code-audit history churn [PATH]           # High-churn files
code-audit history bus-factor             # Knowledge concentration
code-audit history trends                 # Debt trends over time

# Baseline commands
code-audit baseline create [NAME]         # Snapshot current state
code-audit baseline compare [NAME]        # Compare to baseline
code-audit baseline list                  # List baselines
```

---

## Configuration Files

### pyproject.toml
```toml
[tool.code-audit]
# Analyzer thresholds
max_complexity = 15
max_file_lines = 500
max_function_lines = 50
max_duplication_percent = 5

# Fence settings
fences_dir = ".fences"
strict_mode = false

# Governance
deprecation_registry = "deprecation_registry.json"
legacy_routes_budget = 0

# Architecture
allowed_layers = ["api", "service", "domain", "repository", "infrastructure"]
layer_dependencies = {
    "api" = ["service", "domain"],
    "service" = ["domain", "repository"],
    "repository" = ["domain", "infrastructure"],
    "domain" = ["infrastructure"]
}

# Baseline
baseline_dir = ".baselines"
auto_baseline = true
```

### .fences/safety.fence.yaml
```yaml
fences:
  - id: safety_001
    name: "Safety Critical Decorator"
    type: safety_critical
    description: "All G-code functions must use @safety_critical"
    target: "decorator_usage"
    condition: "has_safety_decorator"
    severity: CRITICAL
    owner: "safety-team"

  - id: safety_002
    name: "No Bare Except"
    type: safety_critical
    target: "exception_specificity"
    condition: "no_bare_except"
    severity: ERROR
```

---

## Scoring Rubric (from Design Review)

| Category | Weight | Metrics |
|----------|--------|---------|
| Purpose Clarity | 10% | API discoverability, documentation |
| User Fit | 10% | Route count, complexity |
| Usability | 10% | Startup time, error messages |
| Reliability | 15% | Test coverage, exception handling |
| Maintainability | 15% | File sizes, complexity, duplication |
| Cost Efficiency | 10% | Size metrics, dependency count |
| Safety | 15% | Safety decorator coverage, validation |
| Scalability | 10% | Modular design, coupling metrics |
| Aesthetics | 5% | Naming consistency, organization |

**Score Calculation:**
```python
def calculate_score(metrics):
    weights = {
        'purpose_clarity': 0.10,
        'user_fit': 0.10,
        'usability': 0.10,
        'reliability': 0.15,
        'maintainability': 0.15,
        'cost_efficiency': 0.10,
        'safety': 0.15,
        'scalability': 0.10,
        'aesthetics': 0.05
    }

    return sum(
        metrics[category] * weight
        for category, weight in weights.items()
    )
```

---

## Migration from luthiers-toolbox

```bash
# Step 1: Create migration script
python scripts/migrate_from_ltb.py \
    --source /path/to/luthiers-toolbox/services/api/app/ci \
    --target src/code_audit

# Step 2: Adapt to Analyzer protocol
# Each tool needs to be converted to:
class MyAnalyzer:
    id = "my_analyzer"
    version = "1.0.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # Implementation
        pass

# Step 3: Update imports and paths
# Step 4: Add tests
# Step 5: Update CLI
```

---

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Analyzers Ported | 10+ | Count of working analyzers |
| Fence Types | 5+ | API, Safety, Arch, Perf, Custom |
| Test Coverage | >80% | pytest-cov |
| Documentation | 100% | All public APIs documented |
| CLI Commands | 20+ | Count of subcommands |
| Schema Coverage | 100% | All data structures have schemas |

---

## Next Steps

1. **Immediate:** Review existing code-analysis-tool structure
2. **Week 1:** Port core analyzers (file_sizes, duplication)
3. **Week 2:** Add baseline support and CLI enhancements
4. **Week 3-4:** Implement fence checker framework
5. **Week 5+:** Continue with governance, architecture, strangler modules

The key principle is **incremental value delivery** - each phase should produce usable tooling, not wait for everything to be complete.
