# Deployment Plan: luthiers-toolbox CI Tools → code-analysis-tool

## Current State Analysis

### Already Implemented in code-analysis-tool
| Module | Status | Notes |
|--------|--------|-------|
| `analyzers/complexity.py` | EXISTS | Uses AST-based CC calculation |
| `analyzers/exceptions.py` | EXISTS | Bare except + broad except + swallowed |
| `contracts/load.py` | EXISTS | JSON schema validation |
| `core/runner.py` | EXISTS | Orchestration |
| `core/discover.py` | EXISTS | File discovery |
| `model/finding.py` | EXISTS | Finding dataclass |

### To Be Ported from luthiers-toolbox
| Source | Target | Priority |
|--------|--------|----------|
| `check_file_sizes.py` | `analyzers/file_sizes.py` | P1 |
| `check_duplication.py` | `analyzers/duplication.py` | P1 |
| `fence_checker_v2.py` | `contracts/safety_fence.py` | P1 |
| `check_deprecation_sunset.py` | `governance/deprecation.py` | P2 |
| `legacy_usage_gate.py` | `governance/legacy_usage.py` | P2 |
| `ban_experimental_ai_core_imports.py` | `governance/import_ban.py` | P2 |
| `generate_debt_report.py` | `reports/debt_report.py` | P2 |
| `fence_runner.py` | `contracts/fence_runner.py` | P3 |
| `endpoint_truth_gate.py` | `contracts/endpoint_truth.py` | P3 |
| `inventory_endpoints.py` | `inventory/endpoints.py` | P3 |

---

## Phase 1: Core Analyzers (No External Dependencies)

### 1.1 File Sizes Analyzer

**Source:** `luthiers-toolbox/services/api/app/ci/check_file_sizes.py`
**Target:** `src/code_audit/analyzers/file_sizes.py`

**Adaptation needed:**
```python
# Convert to Analyzer protocol:
class FileSizesAnalyzer:
    id = "file_sizes"
    version = "1.0.0"

    def __init__(self, threshold: int = 500):
        self.threshold = threshold

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings = []
        for f in files:
            if f.suffix != ".py":
                continue
            lines = f.read_text().splitlines()
            if len(lines) > self.threshold:
                findings.append(Finding(
                    analyzer_id=self.id,
                    severity=Severity.WARNING,
                    message=f"File has {len(lines)} lines (threshold: {self.threshold})",
                    location=Location(path=f, line=1, column=1),
                    fingerprint=make_fingerprint(self.id, str(f), "size")
                ))
        return findings
```

### 1.2 Duplication Analyzer

**Source:** `luthiers-toolbox/services/api/app/ci/check_duplication.py`
**Target:** `src/code_audit/analyzers/duplication.py`

**Key logic to port:**
- `_extract_blocks()` - AST block extraction
- `_normalize_ast()` - AST normalization for hashing
- `find_duplicates()` - Hash-based grouping

---

## Phase 2: Safety & Contract Validators

### 2.1 Safety Fence Checker

**Source:** `luthiers-toolbox/services/api/app/ci/fence_checker_v2.py`
**Target:** `src/code_audit/contracts/safety_fence.py`

**Adaptation needed:**
- Integrate with existing `contracts/` module
- Use Finding model instead of FenceViolation
- Configure safety function patterns externally

**Schema addition:** `schemas/safety_fence.schema.json`
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "safety_patterns": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Function name patterns requiring @safety_critical"
    },
    "exclude_suffixes": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Function suffixes to exclude (e.g., _hash, _stub)"
    }
  }
}
```

---

## Phase 3: Governance Gates

### 3.1 Deprecation Sunset

**Source:** `luthiers-toolbox/services/api/app/ci/check_deprecation_sunset.py`
**Target:** `src/code_audit/governance/deprecation.py`

**Schema:** `schemas/deprecation_registry.schema.json`
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["routes"],
  "properties": {
    "routes": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "module", "sunset_date"],
        "properties": {
          "id": {"type": "string"},
          "module": {"type": "string"},
          "sunset_date": {"type": "string", "format": "date"},
          "old_prefix": {"type": "string"},
          "new_prefix": {"type": "string"}
        }
      }
    }
  }
}
```

### 3.2 Legacy Usage Gate

**Source:** `luthiers-toolbox/services/api/app/ci/legacy_usage_gate.py`
**Target:** `src/code_audit/governance/legacy_usage.py`

**Adaptation needed:**
- Make LEGACY_ROUTES configurable via JSON
- Scan roots configurable
- Integrate with Finding model

### 3.3 Import Ban

**Source:** `luthiers-toolbox/services/api/app/ci/ban_experimental_ai_core_imports.py`
**Target:** `src/code_audit/governance/import_ban.py`

**Generalization:**
```python
class ImportBanAnalyzer:
    id = "import_ban"

    def __init__(self, banned_patterns: list[str]):
        self.patterns = [re.compile(p) for p in banned_patterns]

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        # Generic banned import scanner
```

---

## Phase 4: Reporting

### 4.1 Debt Report Generator

**Source:** `luthiers-toolbox/services/api/app/ci/generate_debt_report.py`
**Target:** `src/code_audit/reports/debt_report.py`

**Integration:**
- Use `core.runner.run_scan()` to collect findings
- Transform findings to markdown report
- Add to CLI: `code-audit report --format markdown`

---

## Directory Structure After Deployment

```
src/code_audit/
├── __init__.py
├── __main__.py              # CLI entry point
├── analyzers/
│   ├── __init__.py
│   ├── complexity.py        # EXISTS
│   ├── exceptions.py        # EXISTS
│   ├── file_sizes.py        # NEW (Phase 1)
│   └── duplication.py       # NEW (Phase 1)
├── contracts/
│   ├── __init__.py          # EXISTS
│   ├── load.py              # EXISTS
│   ├── safety_fence.py      # NEW (Phase 2)
│   └── fence_runner.py      # NEW (Phase 3)
├── governance/
│   ├── __init__.py          # NEW
│   ├── deprecation.py       # NEW (Phase 3)
│   ├── legacy_usage.py      # NEW (Phase 3)
│   └── import_ban.py        # NEW (Phase 3)
├── inventory/
│   ├── __init__.py          # NEW
│   └── endpoints.py         # NEW (Phase 3)
├── reports/
│   ├── __init__.py          # NEW
│   └── debt_report.py       # NEW (Phase 4)
├── core/
│   ├── __init__.py          # EXISTS
│   ├── config.py            # EXISTS
│   ├── discover.py          # EXISTS
│   └── runner.py            # EXISTS
├── model/
│   ├── __init__.py          # EXISTS
│   ├── finding.py           # EXISTS
│   └── run_result.py        # EXISTS
└── data/
    ├── schemas/             # JSON schemas for validation
    └── baselines/           # Baseline files for ratchet mode
```

---

## CLI Integration

### Existing CLI
```bash
code-audit scan [PATH]
code-audit validate [FILE]
```

### Proposed Additions
```bash
# Analyzer commands
code-audit analyze complexity [PATH]
code-audit analyze file-sizes [PATH] --threshold 500
code-audit analyze duplication [PATH] --min-lines 6
code-audit analyze exceptions [PATH]

# Contract commands
code-audit fence check [PATH]
code-audit fence list
code-audit endpoint-truth check

# Governance commands
code-audit deprecation check [--warn-only] [--upcoming 30]
code-audit legacy-usage [--budget N]
code-audit import-ban [PATH] --patterns "app._experimental.*"

# Report commands
code-audit report debt [--output FILE]
code-audit report markdown
```

---

## Baseline/Ratchet Mode

All analyzers should support:
1. `--write-baseline` - Snapshot current violations
2. `--baseline FILE` - Compare against baseline, fail only on NEW
3. Baseline files stored in `data/baselines/`

**Baseline schema:** `schemas/baseline.schema.json`
```json
{
  "type": "object",
  "properties": {
    "analyzer_id": {"type": "string"},
    "threshold": {"type": "number"},
    "created_at": {"type": "string", "format": "date-time"},
    "violation_count": {"type": "integer"},
    "violations": {"type": "array"}
  }
}
```

---

## Migration Checklist

### Phase 1 (Priority: High)
- [ ] Port `check_file_sizes.py` → `analyzers/file_sizes.py`
- [ ] Port `check_duplication.py` → `analyzers/duplication.py`
- [ ] Add baseline support to existing analyzers
- [ ] Update `__main__.py` with new CLI commands

### Phase 2 (Priority: Medium)
- [ ] Port `fence_checker_v2.py` → `contracts/safety_fence.py`
- [ ] Create `schemas/safety_fence.schema.json`
- [ ] Add fence CLI commands

### Phase 3 (Priority: Lower)
- [ ] Create `governance/` module
- [ ] Port deprecation, legacy usage, import ban
- [ ] Port endpoint inventory (requires FastAPI introspection)

### Phase 4 (Priority: Final)
- [ ] Port debt report generator
- [ ] Integrate with GitHub Actions workflow template
