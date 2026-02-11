# Alpha-Omega (A-O) Project Handoff

**Project:** Code Analysis Tool
**Repository:** https://github.com/HanzoRazer/code-analysis-tool
**Date:** 2026-02-11
**Status:** Foundation Complete, Implementation Ready

---

## 1. Project Purpose

A unified static analysis toolkit that consolidates technical debt detection, safety contract enforcement, and architectural governance into a single CLI tool.

**Source Material:**
- `luthiers-toolbox/services/api/app/ci/` - 15+ battle-tested CI tools
- Design Review methodology (Purpose Clarity, Safety, Maintainability scoring)
- Strangler Fig pattern for incremental debt elimination

---

## 2. Current State

### Already Implemented
| Module | Location | Status |
|--------|----------|--------|
| Complexity analyzer | `analyzers/complexity.py` | DONE |
| Exception analyzer | `analyzers/exceptions.py` | DONE |
| Contract loader | `contracts/load.py` | DONE |
| Core runner | `core/runner.py` | DONE |
| File discovery | `core/discover.py` | DONE |
| Finding model | `model/finding.py` | DONE |

### Documentation Created
| File | Contents |
|------|----------|
| `docs/TOOL_CATALOG.md` | All tools with CLI, exit codes, dependencies |
| `docs/DEPLOYMENT_PLAN.md` | 4-phase implementation with code examples |
| `docs/ORGANIZATION_PLAN.md` | Full structure, 10 modules, 7-phase plan |

---

## 3. Analyzer Protocol (Critical Pattern)

All analyzers MUST follow this interface:

```python
from pathlib import Path
from code_audit.model.finding import Finding, Severity, Location

class MyAnalyzer:
    id = "my_analyzer"           # Unique identifier
    version = "1.0.0"            # Semver

    def __init__(self, threshold: int = 10):
        self.threshold = threshold

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings = []
        for f in files:
            # Analysis logic here
            if violation_found:
                findings.append(Finding(
                    analyzer_id=self.id,
                    severity=Severity.WARNING,
                    message="Description of issue",
                    location=Location(path=f, line=N, column=1),
                    fingerprint=make_fingerprint(self.id, str(f), "key")
                ))
        return findings
```

---

## 4. Implementation Priority Queue

### P1 - Core Analyzers (Week 1-2)
```
PORT: check_file_sizes.py    -> analyzers/file_sizes.py
PORT: check_duplication.py   -> analyzers/duplication.py
```
No external dependencies. Pure stdlib.

### P2 - Safety Contracts (Week 3-4)
```
PORT: fence_checker_v2.py    -> contracts/safety_fence.py
NEW:  Fence registry system  -> contracts/fence_registry.py
```
Safety-critical function detection, bare except blocking.

### P3 - Governance Gates (Week 5-6)
```
PORT: check_deprecation_sunset.py  -> governance/deprecation.py
PORT: legacy_usage_gate.py         -> governance/legacy_usage.py
PORT: ban_experimental_imports.py  -> governance/import_ban.py
```

### P4 - Architecture (Week 7-8)
```
NEW: dependency_graph.py     -> architecture/dependency_graph.py
NEW: circular_deps.py        -> architecture/circular_deps.py
```

### P5 - Strangler Fig (Week 9-10)
```
NEW: debt_detector.py        -> strangler/debt_detector.py
NEW: plan_generator.py       -> strangler/plan_generator.py
```

### P6 - Reports (Week 11-12)
```
PORT: generate_debt_report.py -> reports/debt_report.py
NEW:  trend_analysis.py       -> reports/trend_analysis.py
```

---

## 5. Baseline/Ratchet Mode (Critical Feature)

All analyzers must support:
```bash
code-audit analyze X --write-baseline   # Snapshot current violations
code-audit analyze X --baseline FILE    # Fail only on NEW violations
```

Baseline JSON structure:
```json
{
  "analyzer_id": "file_sizes",
  "threshold": 500,
  "created_at": "2026-02-11T10:00:00Z",
  "violation_count": 12,
  "violations": [
    {"file": "path/to/file.py", "fingerprint": "abc123..."}
  ]
}
```

---

## 6. Fence Severity Levels

| Level | Exit Code | Meaning |
|-------|-----------|---------|
| INFO | 0 | Informational only |
| WARNING | 1 | Should fix, non-blocking |
| ERROR | 2 | Must fix before merge |
| CRITICAL | 3 | Safety violation |
| BLOCKER | 4 | Immediate CI failure |

---

## 7. CLI Structure Target

```bash
# Core scanning
code-audit scan [PATH]
code-audit scan --analyzers complexity,file_sizes

# Individual analyzers
code-audit analyze complexity [PATH] --threshold 15
code-audit analyze file-sizes [PATH] --threshold 500
code-audit analyze duplication [PATH] --min-lines 6

# Contracts
code-audit fence check [PATH]
code-audit fence list

# Governance
code-audit deprecation check [--warn-only]
code-audit import-ban [PATH] --patterns "app._experimental.*"

# Reports
code-audit report debt [--output FILE]
code-audit report trend [--days 30]
```

---

## 8. Key Source Files to Port

From `luthiers-toolbox/services/api/app/ci/`:

| Source | Lines | Complexity | Notes |
|--------|-------|------------|-------|
| `check_file_sizes.py` | ~80 | Low | Port first |
| `check_duplication.py` | ~150 | Medium | AST hashing |
| `fence_checker_v2.py` | ~200 | Medium | Safety patterns |
| `check_deprecation_sunset.py` | ~120 | Low | Registry-based |
| `generate_debt_report.py` | ~210 | Low | Orchestrator |

---

## 9. Configuration Files

### pyproject.toml section
```toml
[tool.code-audit]
exclude = ["tests/", "migrations/"]
analyzers = ["complexity", "file_sizes", "exceptions"]

[tool.code-audit.complexity]
threshold = 15

[tool.code-audit.file_sizes]
threshold = 500
```

### .fences/safety.fence.yaml
```yaml
id: safety_critical_functions
severity: CRITICAL
patterns:
  - "generate_gcode"
  - "calculate_feeds"
  - "compute_feasibility"
require_decorator: "@safety_critical"
exclude_suffixes: ["_hash", "_stub", "_mock"]
```

---

## 10. Getting Started Commands

```bash
# Clone and setup
cd C:/Users/thepr/Downloads/code-analysis-tool/repo
pip install -e .

# Run existing analyzers
code-audit scan src/

# Verify structure
ls src/code_audit/analyzers/
ls src/code_audit/contracts/
ls src/code_audit/core/

# View documentation
cat docs/TOOL_CATALOG.md
cat docs/DEPLOYMENT_PLAN.md
cat docs/ORGANIZATION_PLAN.md
```

---

## 11. Success Metrics

| Metric | Target |
|--------|--------|
| Analyzers ported | 6 core tools |
| Test coverage | >80% |
| CLI commands | 15+ |
| Baseline support | All analyzers |
| Zero bare excepts | Enforced in CI |

---

## 12. Reference Links

- **Source repo:** `C:/Users/thepr/Downloads/luthiers-toolbox/services/api/app/ci/`
- **Target repo:** `C:/Users/thepr/Downloads/code-analysis-tool/repo/`
- **GitHub:** https://github.com/HanzoRazer/code-analysis-tool

---

## 13. Quick Wins for First Session

1. Copy `check_file_sizes.py` logic into `analyzers/file_sizes.py`
2. Adapt to Analyzer protocol (see Section 3)
3. Add to `__main__.py` CLI
4. Write 3 unit tests
5. Run on luthiers-toolbox as validation

---

*Alpha-Omega: From technical debt to clean architecture*
