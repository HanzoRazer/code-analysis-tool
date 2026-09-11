# Session Bookmark — 2026-09-11

> **Purpose:** snapshot of project state for session continuity after system reset.
> The 2026-02-19 bookmark is kept below, superseded.

---

## Interrupted session

| Field | Value |
|-------|-------|
| **Session** | `5b1d4628-2b05-4e39-92ee-6b0cfb1e23a9` (last active 2026-09-11 08:09 UTC) |
| **Reopen** | `claude --resume 5b1d4628-2b05-4e39-92ee-6b0cfb1e23a9`, or `/resume` and pick it |
| **Cut off during** | a check of a luthiers-toolbox script's CRLF handling (re-run and finished in session `778e3df9`) |
| **main** | `3a4717e` (#31), CI green on both required checks |

It had two threads open: the CRLF endpoint-scan question and the merge train.

---

## 1. CRLF endpoint-scan fix — NOT RESOLVED

The chat claimed the instance fix (strip `\r` in the endpoint scan) was "already done". No repo shows it:

- The script found is luthiers-toolbox `services/api/scripts/build_endpoint_consumer_map.py` (defines `ENDPOINT_ROOTS`). It hasn't changed since #204 (`a2d24bed`, 2026-07-07), and there's no uncommitted edit to it.
- It also can't have the bug. Every file read goes through `read_text()`, which turns `\r\n` into `\n`. Its one subprocess read (`git rev-parse HEAD`) is `.strip()`ped.
- No commit in luthiers-toolbox, CNC-Production-Shop, tap_tone_pi or code-analysis-tool mentions CRLF, `\r`, line endings or an endpoint scan.

So either the fix only existed in the chat's sandbox, or the scan that hit the false zero is a different script.

**Open question for the owner:** which repo and script does that endpoint scan live in?

**Detector follow-up (filed, not built):** a "CRLF in a data file breaks a comparison without normalizing line endings" detector waits until the train drains. It gets grounded against **merged** A (after car 9). It could be a rule on A, an axis on `context_pinned_hash` (which already normalizes line endings to LF, but only for values that reach a hash), or a standalone detector.

---

## 2. Merge train (freeze on new detector work until drained)

| Car | Branch | PR | State |
|-----|--------|----|-------|
| 1 | `fix/utf8-stdout-cp1252` | #30 | merged `38c4ca4`, main CI green |
| 2 | `fix/utf8-file-encoding` | #31 | merged `3a4717e` 2026-09-11 08:13 UTC, main CI green |
| 3 | `feat/pr-scope-dependency-direction` | — | **next**: one commit `78e1f82` on `9e1d2fc`, no PR yet |
| 4 | `feat/silencer-protocol-note` | — | queued |
| 5 | `feat/deployment-watch-coverage-validator` (C) | — | queued. Only conflicting line vs car 2 is `DeploymentAnalyzer.version`, which resolves to `"1.1.0"`. Regenerate its logic-manifest entry on py3.11 |
| 6 | `feat/dangling-reference-analyzer` | — | queued (enum clique) |
| 7 | `feat/unbacked-claim-analyzer` | — | queued (enum clique) |
| 8 | `feat/canonical-pill-analyzer` | — | queued (enum clique) |
| 9 | `feat/unguarded-stdout-encoding-detector` (A) | — | queued; must land after car 1 |
| 10 | `feat/gate-wrong-artifact-detector` (#5) | #32 | **pulled ahead of 3–9 by the owner.** Main merged in (`api.py`/`model` union-resolved), manifests refreshed on py3.11, full suite 1229 passed / 0 failed, dogfood 0 FP. Owner presses merge |
| — | `feat/silent-fallback-rule-sf-001` | #1 closed | branch deleted 2026-09-10; content at `refs/pull/1/head` (`ad561ab`) |
| — | `held/maxfail-ci-surfaces-matrix-fail-fast` | none (held) | `274198b` on `3802ccf`. Snapshot of uncommitted maxfail 1.1.0 arms (matrix `fail-fast`, Makefile, GitLab/CircleCI) that existed on no branch. Rebuild onto main's 2.0.0 after the drain; don't merge as-is |

**Merge button:** owner for cars 1–3, likely 5, 9 and 10. Whether the terminal merges cars 4–8 itself once green gets decided after car 3.

**Per-car loop:** fetch main → confirm main's own CI → merge main into the car (no rebase, no force-push) → on a `patch_input.json` conflict keep the car's manifest; resolve CHANGELOG/enum → refresh manifests on py3.11 if touched → full suite with `CI=true`, `CONFIDENCE_ENTRYPOINTS=src/code_audit/insights/confidence.py`, `PYTHONPATH` pinned to the worktree (`C:/tmp/wt-train`) → push → open PR → required checks (`Run pytest (Python 3.11)`, `rule-registry-sync`) green → merge.

**Collision classes:**
- **Enum clique:** cars 6–10 all conflict on `model/__init__.py`, `api.py` and both confidence manifests. Each car pays one mechanical re-resolution.
- **`patch_input.json` fixed path:** every pair inside the root group and every pair inside the `cbsp21/` group conflicts.
- **Real code overlap:** `deployment.py` (car 2 × car 5).

---

## Next step

1. Merge #32 (car 10) once it's green. The owner presses the button.
2. Run the car 3 loop and open its PR. Cars 6–9 will each re-resolve the enum clique against car 10 once it lands.
3. Still pending: the CRLF question above.

**Main checkout cleanup (not done):** the working tree on `feat/gate-wrong-artifact-detector` still has uncommitted copies that are superseded: `pr_scope.py` and its test (by #20), `patch_input_v2.*` drafts and the pr-scope edits in `__main__.py`/`api.py`/`__init__.py` (on main), plus maxfail 1.1.0 (now on the held branch). Once the checkout is pulled up to date after #32 merges, they can be discarded.

---

# Previous bookmark — 2026-02-19 (superseded)

> Supplements `docs/ENGINEER_HANDBACK_2026-02-14.md` (unchanged; covers sessions 02-14 through 02-16).

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
