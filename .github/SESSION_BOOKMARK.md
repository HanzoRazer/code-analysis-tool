# Session Bookmark — 2026-02-19

> **Purpose:** snapshot of project state for session continuity after system reset.
> Supplements `docs/ENGINEER_HANDBACK_2026-02-14.md` (unchanged; covers sessions 02-14 through 02-16).

---

## Current state

| Field | Value |
|-------|-------|
| **Repo** | `c:\Users\thepr\Downloads\code-analysis-tool` |
| **Branch** | `main` (uncommitted changes from 2026-02-19 session) |
| **Python** | 3.14.0 (local), 3.13.7 (documented target) |
| **Package** | `code_audit` (installable from `src/`) |
| **Test suite** | 902 collected, **877 passed**, 4 skipped, **21 failed** (all 21 pre-existing — zero caused by this session) |
| **signal_logic_version** | `"signals_v2"` in `src/code_audit/model/run_result.py:32` |

---

## What was shipped in the 2026-02-19 session

### 1. Exit-code governance (manifest-gated, CI-deterministic) — COMPLETE

Locks exit-code thresholds and severity-to-exit-code mapping behind a manifest gate.

| File | Action |
|------|--------|
| `src/code_audit/policy/exit_codes.py` | **Created.** `ExitCodePolicy`, `DEFAULT_POLICY`, `exit_code_for_worst_severity()`, `worst_severity_from_counts()` |
| `src/code_audit/policy/thresholds.py` | **Created.** `ThresholdPolicy`, `DEFAULT_POLICY`, `exit_code_from_score()`, `tier_from_score()` |
| `scripts/refresh_exit_code_policy_manifest.py` | **Created.** Generates composite SHA-256 manifest for both policy modules |
| `tests/contracts/exit_code_policy_manifest.json` | **Created.** Manifest artifact |
| `tests/test_exit_code_policy_manifest_gate.py` | **Created.** Fails if policy logic changes without `signal_logic_version` bump |
| `tests/test_exit_code_behavior_contract.py` | **Created.** 15 tests locking score→exit-code + severity→exit-code mappings |
| `src/code_audit/__main__.py` | **Modified.** Imports wired to policy modules; CI mode returns `max(score_ec, sev_ec)` |
| `tests/test_api_cli_parity_ci.py` | **Modified.** Accept exit code 2 (severity policy) |
| `tests/test_i18n_keys_resolve.py` | **Modified.** Accept exit code 2 |
| `tests/test_i18n_key_prefix_no_signal_dot.py` | **Modified.** Accept exit code 2 |

### 2. CI-mode environment lock (--ci hard-fails unless CI=true) — COMPLETE

When `--ci` is passed, the `CI` environment variable must equal `"true"` (case-insensitive, trimmed). Everything else is exit-code 2.

| File | Action |
|------|--------|
| `src/code_audit/contracts/ci_mode.py` | **Created.** `CIModeRequiredError` exception, `require_ci_true(env=None)` guard |
| `tests/test_ci_mode_env_lock.py` | **Created.** 28 tests: accepted values (true/True/TRUE/padded), rejected values (empty/false/0/1/yes/on/prod/ci/Truee/tru), unset, message contracts |
| `src/code_audit/__main__.py` | **Modified.** New `_require_ci_env()` helper imported and wired at 3 enforcement points: scan subcommand, default positional mode, debt commands (scan/snapshot/compare) |

**Key design:** This is the *reverse* of the existing `_require_ci_flag()`. The existing guard errors when CI env *is* active but `--ci` was *not* passed. The new guard errors when `--ci` *was* passed but CI env is *not* `"true"`.

### 3. Observer workflow — NO CHANGES NEEDED

The observer workflow (`.github/workflows/contract-parity-main-observer.yml`, 1938 lines) already has full `drift-ci-mode` support:

- Job-level `env: CI: "true"` (line 21)
- Bash-level CI=true check (lines 47–53)
- JS-level CI=true check in red-path script (lines 113–120) and green-path script (lines ~1310)
- `"drift-ci-mode": "true"` in all `rewriteMarkerBlock()` calls (red + green paths)
- `<!-- drift-ci-mode: true -->` in escalation and resolved comments
- `assertMarkerExactlyOnce(comment, "drift-ci-mode", ...)` uniqueness checks

---

## Pre-existing test failures (21 total — none caused by this session)

### Category 1: `--out must be a relative path` (14 failures)

Tests pass absolute paths to `debt snapshot --out` while `CI=true` is in the env (set by the shared `_run()` helper). The `_reject_unsafe_out_path` guard rejects absolute paths in CI mode.

**Affected tests:**
- `test_cli_api_parity_debt_ci.py` (2 tests)
- `test_debt_snapshot_ci.py` (2 tests)
- `test_debt_snapshot_schema_version_enforcement.py` (3 tests)
- `test_exit_code_contract.py` (2 tests)
- `test_exit_codes_contract.py::TestDebtExitCodes` (3 tests)
- `test_contract_parity_cli_api_debt_ci.py` (1 test)
- `test_contract_parity_cli_api_scan_ci.py` (1 test — scan `--out` path resolves relative to `--root`, not `cwd`)

**Fix:** Tests need to either use relative `--out` paths with appropriate `cwd`, or not set `CI=true`/`--ci` in the subprocess env.

### Category 2: `CI environment requires deterministic mode` (2 failures)

`test_exit_codes_contract.py::TestDebtScanExitCodes` — the shared `_run()` helper sets `env["CI"] = "true"` but two `debt scan` tests don't pass `--ci`. The existing `_require_ci_flag` guard triggers.

**Fix:** Either pass `--ci` or don't inject `CI=true` for non-CI-mode tests.

### Category 3: Scan `--out` file not written (2 failures)

`test_cli_api_parity_scan_ci.py` and `test_contract_parity_cli_api_scan_ci.py` — in CI mode, `--out` path resolves relative to `scan_root` (`--root` dir), not `cwd`. Tests expect the file at `cwd/artifacts/` but it resolves to `scan_root/artifacts/`.

### Category 4: Stale manifests (2 failures)

- `test_analyzer_registry_contract.py` — Vue analyzers (`VueComponentAnalyzer`, `VueCouplingAnalyzer`) discovered by `pkgutil` but not registered in `_DEFAULT_ANALYZERS`
- `test_confidence_policy_requires_signal_logic_bump.py` — stale confidence hash

### Category 5: Logic manifest (1 failure)

- `test_version_bump_enforcement.py` — stale `tests/contracts/logic_manifest.json` (needs `python scripts/refresh_logic_manifest.py`)

---

## Files modified but uncommitted (2026-02-19)

| File | Change |
|------|--------|
| `src/code_audit/contracts/ci_mode.py` | **New** — guard module |
| `src/code_audit/__main__.py` | **Modified** — added import + `_require_ci_env()` + 3 enforcement call sites |
| `src/code_audit/policy/exit_codes.py` | **New** — exit code policy |
| `src/code_audit/policy/thresholds.py` | **New** — threshold policy |
| `scripts/refresh_exit_code_policy_manifest.py` | **New** |
| `tests/contracts/exit_code_policy_manifest.json` | **New** |
| `tests/test_exit_code_policy_manifest_gate.py` | **New** |
| `tests/test_exit_code_behavior_contract.py` | **New** |
| `tests/test_ci_mode_env_lock.py` | **New** — 28 guard tests |
| `tests/test_api_cli_parity_ci.py` | **Modified** — accept exit code 2 |
| `tests/test_i18n_keys_resolve.py` | **Modified** — accept exit code 2 |
| `tests/test_i18n_key_prefix_no_signal_dot.py` | **Modified** — accept exit code 2 |

---

## Enforcement points in `__main__.py`

The CLI now has **two directional CI guards** applied at the same 3 enforcement points:

| Point | Guard 1: `_require_ci_flag` (pre-existing) | Guard 2: `_require_ci_env` (new) |
|-------|-----------------------------|----------------------------|
| **Scan subcommand** (~line 1661) | CI env active → must pass `--ci` | `--ci` passed → CI env must be `"true"` |
| **Default positional** (~line 1749) | Same | Same |
| **Debt commands** (~line 1300) | Same (scan/snapshot/compare) | Same |

---

## Guard module API reference

```python
# src/code_audit/contracts/ci_mode.py

class CIModeRequiredError(RuntimeError):
    def __init__(self, actual: str | None) -> None: ...
    actual: str | None  # the raw CI env value, or None if unset

def require_ci_true(env: dict[str, str] | None = None) -> None:
    """Raises CIModeRequiredError if CI != "true" (case-insensitive, trimmed)."""
```

---

## What to do next (recommended sequence)

1. **Fix pre-existing test failures** — The 14 `--out` path failures and 2 `_require_ci_flag` failures are the highest priority. Fix pattern: use relative `--out` paths with `cwd=` set, or adjust `_reject_unsafe_out_path` base_dir logic.
2. **Register Vue analyzers** or exclude them — `VueComponentAnalyzer` and `VueCouplingAnalyzer` are discovered by `pkgutil` but not in `_DEFAULT_ANALYZERS`.
3. **Refresh stale manifests** — `python scripts/refresh_logic_manifest.py`.
4. **Commit the 2026-02-19 changes** — All new files + modifications listed above.
5. **Continue handback tightening sequence** — Next items from the handback document.

---

## Runtime

- Python `>=3.11` (CI tests on 3.11, local is 3.14.0)
- **Stdlib-only at runtime** — no external dependencies
- Dev deps: `pytest>=7.0`, `jsonschema>=4.0`
- Test command: `python -m pytest` (from repo root; `pyproject.toml` has `--maxfail=1`)
- Override maxfail for full picture: `python -m pytest --override-ini="addopts=" --tb=no -q`
