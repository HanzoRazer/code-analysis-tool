# Test Failure Remediation Plan

> **27 failures** across 11 test files — all environmental/platform, not logic bugs.  
> Generated: 2026-03-01 · Suite: 998 passed, 27 failed, 3 skipped (1192s)

---

## Root Cause Summary

| # | Root Cause | Failures | Fix Complexity |
|---|-----------|----------|----------------|
| 1 | Absolute `--out` path rejected in CI mode | 16 | Low — relative paths or env cleanup |
| 2 | No output file (cascade of #1) | 7 | Low — same fix as #1 |
| 3 | `_require_ci_flag` blocks non-`--ci` commands | 4 | Low — monkeypatch or pass `--ci` |
| 4 | pytest 9.0.2 `--collect-only -q` format change | 1 | Low — parse new format |

**Common thread:** User shell has `CI=true` set globally. The CLI's `_reject_unsafe_out_path()` and `_require_ci_flag()` in `src/code_audit/__main__.py` enforce CI-mode constraints that conflict with how tests construct paths via `tmp_path`.

---

## RC-1: Absolute `--out` path rejected in CI mode (16 failures)

**Mechanism:** `_reject_unsafe_out_path()` (line 100 of `__main__.py`) rejects absolute paths when `CI=true`. Tests pass `str(tmp_path / "file.json")` which expands to `C:\Users\...\pytest-...\file.json`.

**Fix strategy:** For each subprocess invocation, either:
- A) Set `cwd=tmp_path` and use a **relative** `--out` path, or
- B) Remove `CI` / `CODE_AUDIT_DETERMINISTIC` from the test's env dict

### RC-1a: `test_debt_snapshot_ci.py` (2 tests)

- [ ] `test_debt_snapshot_out_ci_is_deterministic` — passes `--out str(tmp_path / "snap1.json")` (absolute)
  - Fix: change `_run()` helper to accept `cwd` kwarg, invoke with `cwd=tmp_path`, use `--out snap1.json`
- [ ] `test_debt_compare_file_vs_file` — same pattern with `baseline.json` / `current.json`
  - Fix: same `cwd` approach

### RC-1b: `test_debt_snapshot_schema_version_enforcement.py` (3 tests)

- [ ] `test_debt_compare_rejects_wrong_schema_version_in_baseline`
- [ ] `test_debt_compare_rejects_missing_schema_version_in_baseline`
- [ ] `test_debt_compare_rejects_wrong_schema_version_in_current`

All three first create a snapshot via `_run(["debt", "snapshot", ..., "--out", str(current)])` with an absolute path. The snapshot step fails before the schema-version check is reached.

- Fix: update `_run()` to accept `cwd`, pass `cwd=tmp_path`, use relative `--out` names

### RC-1c: `test_exit_code_contract.py` (2 tests)

- [ ] `test_debt_compare_same_snapshot_returns_0`
- [ ] `test_debt_compare_new_debt_returns_1`

Same pattern — `_run(["debt", "snapshot", ..., "--out", str(baseline)])` with absolute path.

- Fix: either add `cwd` to `_run()` or strip `CI` from env in these tests

### RC-1d: `test_exit_codes_contract.py::TestDebtExitCodes` (3 tests)

- [ ] `test_debt_compare_clean_vs_baseline_returns_0`
- [ ] `test_debt_compare_with_new_debt_returns_1`
- [ ] `test_debt_compare_missing_baseline_returns_2`

- Fix: update `_run()` to support `cwd`, use relative paths

### RC-1e: `test_contract_parity_cli_api_debt_ci.py` (1 test)

- [ ] `test_contract_parity_debt_snapshot_ci` — `--out str(snap_file)` is absolute
  - Fix: use `cwd=tmp_path` + relative `--out baseline.json`

### RC-1f: `test_cli_api_parity_debt_ci.py` (2 tests)

- [ ] `test_snapshot_json_matches_api` — uses `--out "artifacts/snapshot.json"` with `cwd=tmp_path` (already relative — but `_reject_unsafe_out_path` also checks `base_dir=target` resolution, which may fail on Windows path normalization)
- [ ] `test_snapshot_deterministic_across_runs` — same pattern

Investigation needed: These tests already use relative `--out` with `cwd=tmp_path`. The failure may be in the `is_relative_to(allowed)` check where `allowed = (target / "artifacts").resolve()` and `target` is the `work` dir (a copy of the fixture), not `tmp_path`.

- Fix: verify that `--out artifacts/snapshot.json` resolves within `target/artifacts/` (the scan root, not `cwd`)

### RC-1g: Scan parity / scan CI tests with `FileNotFoundError` (3 tests)

These fail because the subprocess exits before writing the output file:

- [ ] `test_cli_api_parity_scan_ci.py::test_default_and_scan_subcommand_produce_same_result`
- [ ] `test_contract_parity_cli_api_scan_ci.py::test_contract_parity_scan_subcommand_ci`
- [ ] `test_contract_parity_cli_api_scan_ci.py::test_contract_default_and_subcommand_produce_same_result`

The scan subcommand passes `--out "artifacts/result.json"` which is relative, but `--root str(workdir)` is absolute. The `_reject_unsafe_out_path` bases its check on `scan_root`, so the relative out path should work — but `_require_ci_flag` may reject the command because `CI=true` is set but the test doesn't always pass `--ci`.

- Fix: ensure `--ci` is always passed when `CI=true` env is inherited, or scrub `CI` from env

---

## RC-2: Scan subprocess produces no output file (4 failures)

**Mechanism:** `_require_ci_flag()` (line 74) returns `ExitCode.ERROR` when `CI=true` is in the environment but `--ci` wasn't passed. The subprocess exits 2 immediately; no output file is written; the test then gets `FileNotFoundError` trying to read it.

### RC-2a: `test_exceptions_analyzer_pipeline.py` (4 tests)

- [ ] `test_scan_finds_exceptions_and_emits_signal`
- [ ] `test_scan_marks_swallowed_errors`
- [ ] `test_signal_evidence_emits_summary_with_counts`
- [ ] `test_exceptions_card_subtext_is_strong_when_swallowed_present`

All use `_run_scan(fixture_root, out)` which calls `python -m code_audit scan --root ... --out str(out)` without `--ci` and with `{**os.environ}` (inheriting `CI=true`).

- Fix (option A): Add `--ci` to the subprocess args in `_run_scan()`
- Fix (option B): Strip `CI` and `CODE_AUDIT_DETERMINISTIC` from the env dict
- Fix (option C): Use relative `--out` path with `cwd=tmp_path` and add `--ci`

---

## RC-3: `_require_ci_flag` blocks in-process `main()` calls (4 failures)

**Mechanism:** `test_strangler.py::TestDebtCLI` calls `main(["debt", "scan", ...])` directly (in-process). Since `CI=true` is in `os.environ`, `_require_ci_flag()` demands `--ci` but none of these tests pass it.

### RC-3a: `test_strangler.py::TestDebtCLI` (4 tests)

- [ ] `test_debt_scan_clean`
- [ ] `test_debt_scan_violation`
- [ ] `test_debt_snapshot_and_compare`
- [ ] `test_debt_compare_new_debt_exits_1`

- Fix: Add a `monkeypatch` fixture (or `@pytest.fixture(autouse=True)`) to `TestDebtCLI` that does `monkeypatch.delenv("CI", raising=False)` and `monkeypatch.delenv("CODE_AUDIT_DETERMINISTIC", raising=False)` before each test

---

## RC-4: pytest 9.0.2 `--collect-only -q` format change (1 failure)

**Mechanism:** `test_contract_manifest_self_consistency.py::test_dedicated_gate_files_are_collected_by_pytest_in_ci` runs `pytest --collect-only -q` and parses lines looking for `::` (nodeID format). In pytest 9.0.2, `-q` outputs `tests/file.py: <count>` instead of `tests/file.py::test_name`. No lines contain `::`, so the test concludes all 5 gate files produced zero tests.

- [ ] `test_dedicated_gate_files_are_collected_by_pytest_in_ci`

- Fix (option A — recommended): Remove `-q` flag so output uses full `<file>::<test>` format
- Fix (option B): Parse the `file: N` format — if `N > 0`, the file contributed tests
- Fix (option C): Use `--collect-only` without `-q` and grep for `::` lines

---

## Cross-cutting fix: conftest.py CI environment guard

Instead of fixing each test file individually, a single `conftest.py` auto-use fixture would prevent CI env leakage into all tests:

```python
# tests/conftest.py
import pytest

@pytest.fixture(autouse=True)
def _clean_ci_env(monkeypatch):
    """Prevent ambient CI=true from breaking tests that don't expect it."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("CODE_AUDIT_DETERMINISTIC", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
```

This would fix **RC-1, RC-2, and RC-3** (26 of 27 failures) in one shot. Tests that explicitly need CI mode already set it in their own `_cli_env()` subprocess env dicts, so they'd be unaffected.

**Tradeoff:** The `test_dedicated_gate_files_are_collected_by_pytest_in_ci` test (RC-4) is *designed* to run only under `CI=true` — this fixture would cause it to silently skip. That test needs the separate `-q` format fix regardless.

---

## Execution Order

| Phase | Tasks | Tests fixed |
|-------|-------|-------------|
| **Phase 1** | Create `tests/conftest.py` with CI-env cleanup fixture | 26 |
| **Phase 2** | Fix `test_dedicated_gate_files_are_collected_by_pytest_in_ci` `-q` parsing | 1 |
| **Phase 3** | Full suite verification | — |

Estimated effort: ~30 minutes implementation + ~20 minutes test run.
