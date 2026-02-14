# Executive Summary: Code-Analysis-Tool Rehydration Artifacts

**Prepared for**: Sandbox Operator
**Purpose**: Complete artifact inventory for governed semantic mode rehydration

---

## 1. Version Anchors

| Anchor | Value | Source |
|--------|-------|--------|
| `signal_logic_version` | `signals_v1` | All three manifests |
| `schema_version` | `run_result_v1` | Golden fixtures (e.g., `dead_code_hot_run_result.json:171`) |
| `engine_version` | `engine_v1` | Golden fixtures (run.engine_version) |
| `copy_version` | `i18n@dev` | Golden fixtures (run.copy_version) |
| Release Tags | **None** | `git tag -l` returns empty |
| Baseline Snapshot Hash | **Not applicable** | No tag-based snapshots exist yet |

---

## 2. Three Manifests

### 2.1 Golden Fixtures Manifest
**Path**: `tests/contracts/golden_fixtures_manifest.json`

| Field | Value |
|-------|-------|
| `signal_logic_version` | `signals_v1` |
| Fixture count | 14 files |
| Hash algorithm | SHA-256 |

**Fixture files (all under `tests/fixtures/expected/`):**
1. `clean_project_run_result.json`
2. `complexity_hot_run_result.json`
3. `dead_code_clean_run_result.json`
4. `dead_code_hot_run_result.json`
5. `duplication_run_result.json`
6. `global_state_clean_run_result.json`
7. `global_state_hot_run_result.json`
8. `import_ban_run_result.json`
9. `large_file_run_result.json`
10. `mixed_severity_run_result.json`
11. `safety_fence_run_result.json`
12. `sample_repo_exceptions_run_result.json`
13. `security_clean_run_result.json`
14. `security_hot_run_result.json`

### 2.2 Translator Policy Manifest
**Path**: `tests/contracts/translator_policy_manifest.json`

```json
{
  "policy_hash": "sha256:6d2671b0ed5e95ed7d724ce86d417059ac6a25f4cfd68fa06a537f760d976c36",
  "signal_logic_version": "signals_v1"
}
```

### 2.3 Logic Manifest (Analyzer Registry)
**Path**: `tests/contracts/logic_manifest.json`

| Field | Value |
|-------|-------|
| `signal_logic_version` | `signals_v1` |
| Analyzer count | 8 |

---

## 3. Translator Policy Surface
**Source**: `src/code_audit/insights/translator.py`

### 3.1 Severity Ranking (`_severity_rank`)
```
CRITICAL → 4
HIGH     → 3
MEDIUM   → 2
LOW      → 1
INFO     → 0
```

### 3.2 Risk Level Mapping (`_risk_from_worst_severity`)
```
HIGH/CRITICAL → red
MEDIUM        → yellow
LOW/INFO      → green
```

### 3.3 Urgency Mapping (`_urgency_from_severity`)
```
CRITICAL/HIGH → important
MEDIUM        → recommended
LOW/INFO      → optional
```

### 3.4 Rule Orders

| Analyzer | Rule Order Constant | Rules (in order) |
|----------|---------------------|------------------|
| Global State | `_GST_RULE_ORDER` | `GST_MUTABLE_DEFAULT_001` → `GST_MUTABLE_MODULE_001` → `GST_GLOBAL_KEYWORD_001` |
| Dead Code | `_DC_RULE_ORDER` | `DC_UNREACHABLE_001` → `DC_IF_FALSE_001` → `DC_ASSERT_FALSE_001` |
| Security | `_SEC_RULE_ORDER` | `SEC_HARDCODED_SECRET_001` → `SEC_EVAL_001` → `SEC_SUBPROCESS_SHELL_001` → `SEC_SQL_INJECTION_001` → `SEC_PICKLE_LOAD_001` → `SEC_YAML_UNSAFE_001` |

### 3.5 Evidence Summary Keys

| Analyzer | Summary Keys |
|----------|-------------|
| Global State | `mutable_default_count`, `module_mutable_count`, `global_keyword_count` |
| Dead Code | `unreachable_count`, `if_false_count` |
| Security | `hardcoded_secret_count`, `eval_exec_count`, `subprocess_shell_count`, `sql_injection_count`, `pickle_load_count`, `yaml_unsafe_count` |
| Exceptions | `swallowed_count`, `logged_count` |

### 3.6 Copy-Key Contract Constants
```python
EVIDENCE_TITLE_KEY_FIELD = "title_key"
EVIDENCE_SUMMARY_KEY_FIELD = "summary_key"
EVIDENCE_WHY_KEY_FIELD = "why_key"
EVIDENCE_ACTION_FIELD = "action"
EVIDENCE_ACTION_TEXT_KEY_FIELD = "text_key"
EVIDENCE_I18N_TITLE_SUFFIX = ".title"
EVIDENCE_I18N_SUMMARY_SUFFIX = ".summary"
EVIDENCE_I18N_WHY_SUFFIX = ".why"
EVIDENCE_I18N_ACTION_TEXT_SUFFIX = ".action.text"
```

### 3.7 `_COPY_PREFIX` (i18n key prefixes)
```python
COMPLEXITY   → "signals.complexity"
EXCEPTIONS   → "signals.exceptions"
SECURITY     → "signals.security"
SAFETY       → "signals.safety"
GLOBAL_STATE → "signals.global_state"
DEAD_CODE    → "signals.dead_code"
```

---

## 4. Analyzer Registry Snapshot

| Class Name | Module | Version | Logic Hash (truncated) |
|------------|--------|---------|------------------------|
| ComplexityAnalyzer | `code_audit.analyzers.complexity` | 1.0.0 | `8a962830...` |
| DeadCodeAnalyzer | `code_audit.analyzers.dead_code` | 1.0.0 | `e2b51f7a...` |
| DuplicationAnalyzer | `code_audit.analyzers.duplication` | 1.0.0 | `154c3907...` |
| ExceptionsAnalyzer | `code_audit.analyzers.exceptions` | 1.0.0 | `f1437c28...` |
| FileSizesAnalyzer | `code_audit.analyzers.file_sizes` | **1.1.0** | `49c38f06...` |
| GlobalStateAnalyzer | `code_audit.analyzers.global_state` | 1.0.0 | `50c60b68...` |
| RoutersAnalyzer | `code_audit.analyzers.routers` | 1.0.0 | `aacf8a41...` |
| SecurityAnalyzer | `code_audit.analyzers.security` | 1.0.0 | `9b675949...` |

**Notable**: `FileSizesAnalyzer` is at v1.1.0; all others at v1.0.0.

---

## 5. Golden Fixture Directory Structure

```
tests/
└── fixtures/
    └── expected/
        ├── clean_project_run_result.json     (baseline clean)
        ├── complexity_hot_run_result.json
        ├── dead_code_clean_run_result.json
        ├── dead_code_hot_run_result.json     (has findings)
        ├── duplication_run_result.json
        ├── global_state_clean_run_result.json
        ├── global_state_hot_run_result.json
        ├── import_ban_run_result.json
        ├── large_file_run_result.json
        ├── mixed_severity_run_result.json
        ├── safety_fence_run_result.json
        ├── sample_repo_exceptions_run_result.json
        ├── security_clean_run_result.json
        └── security_hot_run_result.json
```

**Schema**: All fixtures conform to `run_result_v1` with `signal_logic_version: signals_v1`.

---

## 6. CLI Exit Policy Snapshot

### 6.1 Exit Codes (`src/code_audit/utils/exit_codes.py`)
```python
class ExitCode(IntEnum):
    SUCCESS = 0    # No violations detected
    VIOLATION = 1  # Policy/contract failure
    ERROR = 2      # Usage error, missing file, runtime failure
```

### 6.2 Score Thresholds (`src/code_audit/policy/thresholds.py`)
```python
class ScoreThresholds:
    green_min: int = 75   # ≥75 → GREEN
    yellow_min: int = 55  # 55-74 → YELLOW
                          # <55 → RED
```

### 6.3 Tier → Exit Code Mapping
```
GREEN  → ExitCode.SUCCESS (0)
YELLOW → ExitCode.VIOLATION (1)
RED    → ExitCode.ERROR (2)
```

---

## 7. Rehydration Readiness Assessment

| Requirement | Status | Notes |
|-------------|--------|-------|
| Version anchors documented | ✅ Complete | `signals_v1`, `run_result_v1`, `engine_v1` |
| Golden fixtures manifest | ✅ Complete | 14 fixtures, all hash-guarded |
| Translator policy manifest | ✅ Complete | Policy hash tracked |
| Logic manifest | ✅ Complete | 8 analyzers tracked |
| CLI exit policy | ✅ Complete | 3-code system with score thresholds |
| Release tags | ⚠️ Missing | No tags exist yet |
| Baseline snapshot | ⚠️ N/A | Requires first tagged release |

---

## 8. Recommended Next Steps

1. **Create initial release tag** (e.g., `v0.1.0`) to establish baseline snapshot hash
2. **Generate `cbsp21_patch_manifest_v1`** if incremental patching is planned
3. **Run contract tests** to verify all manifest hashes match current code:
   ```bash
   pytest tests/test_*_contract*.py -v
   ```
