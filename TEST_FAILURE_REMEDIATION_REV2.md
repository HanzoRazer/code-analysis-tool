# Test Failure Remediation — Revision 2

**Reviewed:** 2026-07-23 · **Supersedes:** `TEST_FAILURE_REMEDIATION.md` (2026-03-01)
**Status of prior plan:** never executed — `tests/conftest.py` does not exist anywhere in the repo.
**Correction (same day):** §2 blast-radius claim revised after adversarial review — see §2.1.

---

## 1. What was verified against the current tree

| Claim from Rev 1 | Verified? |
|---|---|
| 27 failed, 3 skipped | ✅ `pytest_full_run.txt` contains exactly 27 `F` and 3 `s` |
| `_require_ci_flag` at `__main__.py:74` | ✅ present, line 74 |
| `_reject_unsafe_out_path` at `__main__.py:100` | ✅ present, line 100 |
| Phase 1 fix applied | ❌ **no `conftest.py` exists in the repo** |

The diagnosis is still live and the mechanism is unchanged. Nothing was fixed.

**Staleness caveat:** the run is dated 2026-03-01 — roughly 4.7 months old. The
`F`/`s` counts and the two guard functions still match, so the *shape* holds, but
the failure list has not been re-observed since. Re-run before executing, and
treat any new failure as unaudited (see §4).

---

## 2. ⛔ The cross-cutting fix in Rev 1 must not be applied as written

Rev 1 proposes an autouse fixture deleting `CI`, `CODE_AUDIT_DETERMINISTIC`, and
`GITHUB_ACTIONS` for **every test**, claiming it fixes 26 of 27 failures.

Do **not** apply it. Even at corrected severity (below), one verified forged green
plus four silent strictness downgrades is enough to reject a global scrub.

Rev 1 noticed one instance and understated it: it says the RC-4 test "would
silently skip." It would not skip. It would **pass**.

`tests/test_contract_manifest_self_consistency.py:370`:

```python
if os.environ.get("CI", "").lower() not in ("true", "1"):
    return
```

That is an early `return`, not `pytest.skip()`. A skip is visible in the summary
line as `s`. A `return` renders as `.` — **indistinguishable from a real pass.**

### 2.1 Blast radius — verified split (not “six forged greens”)

Six files gate on ambient `CI`. They do **not** all share the same mechanism.
Verified against the tree:

| File | Mechanism | Result when `CI` deleted |
|---|---|---|
| `test_contract_manifest_self_consistency.py:371` | bare `return` | **forged green** — reports `.` |
| `test_release_bom_contract.py:42` | helper `return False, ""` | strictness downgrade — CI-only asserts stop firing; test still runs |
| `test_release_openapi_registry_matches_snapshot.py:51` | helper `return False` | strictness downgrade |
| `test_confidence_policy_requires_signal_logic_bump.py:44` | `_require_entrypoints_in_ci()` no-ops | strictness downgrade |
| `test_confidence_golden_requires_confidence_version_bump.py` | same | strictness downgrade |
| `test_ci_env_contracts.py:29` | `pytest.skip("Not running in CI")` | **already correct** — shows as `s` |

**Score:** one forged green, four silent strictness downgrades, one already doing
the right thing. The earlier claim that “all six become no-ops that report green”
was wrong on five of six.

**How that over-claim happened (same shape as Rev 1’s error):** grepped six
`os.environ.get("CI"` hits, read **one** file in detail, asserted that mechanism
for all six. Rev 1 generalized “tests that need CI set it themselves” from
subprocess tests to all tests. Rev 2 initially generalized “early return forges
green” from one file to six. Same over-claim shape, opposite direction — a claim
stronger than its evidence.

These remain the **highest-value** release/governance gates. Autouse is still
rejected: it manufactures one green and silently weakens four others.

Rev 1's justification — *"tests that explicitly need CI mode already set it in
their own `_cli_env()` subprocess env dicts"* — is true only for **subprocess**
tests. It does not hold for in-process `os.environ` readers. That claim is the
load-bearing error in Rev 1.

---

## 3. Corrected approach

**Scope the fixture instead of applying it globally.** The failing tests are a
known, enumerated set; the CI-gated governance tests are a known, disjoint set.

### Phase 0 — do this first, regardless of which Phase 1 you pick

Give absence a signature at every ambient-CI early-exit that currently forges
pass or soft-disables without a skip:

1. **Required:** convert the bare `return` in
   `test_contract_manifest_self_consistency.py` to `pytest.skip(...)`.
2. **Tagged-CI early exits:** `test_release_bom_contract.py` call-site
   `if not is_tagged: return` → `pytest.skip(...)` (four tests). Soft-exit of
   missing OpenAPI artifacts in `test_release_openapi_registry_matches_snapshot.py`
   → `pytest.skip(...)` (match logic still runs when files exist).
3. **No-op (already correct):** `test_ci_env_contracts.py` already skips.
4. **No-op (must keep running locally):** confidence policy / golden version-bump
   files have no early-exit — only `_require_entrypoints_in_ci()` softens when
   `CI` is unset. Skipping the whole test when not CI would disable the bump
   gates locally. Entrypoint CI strictness already has a skip signature via
   `test_ci_env_contracts.py`.

Example for the forged-green site:

```python
if os.environ.get("CI", "").lower() not in ("true", "1"):
    pytest.skip("CI-gated governance check; set CI=true to run")
```

This is the durable fix. After it, any future change that disables these gates
shows up as `s` instead of vanishing into the dots. It is correct regardless of
what Phase 1 decides.

### Phase 1 — opt-in fixture, not autouse (targets RC-1, RC-2, RC-3)

```python
# tests/conftest.py
import pytest

@pytest.fixture
def clean_ci_env(monkeypatch):
    """Opt-in: strip ambient CI vars for tests that construct absolute tmp_path
    --out arguments. NOT autouse — see Rev 2 §2: a global scrub forges green on
    the collection gate and silently downgrades four other CI-gated contracts."""
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("CODE_AUDIT_DETERMINISTIC", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
```

Apply it explicitly to the affected classes/tests only (RC-1a…RC-1g, RC-2a, RC-3a).
More edits than Rev 1, but the blast radius is exactly the tests being fixed.

Treat “26 fixed” as a **hypothesis from the March inventory**, not a target.
RC-1f sits inside that set and may need a path-base fix instead (§4).

*Alternative, if autouse is still preferred for ergonomics:* make it autouse but
opt-out-able, and add `pytestmark = pytest.mark.usefixtures("preserve_ci_env")`
to the governance files that must see ambient `CI`. Only acceptable **with**
Phase 0 complete. Prefer opt-in.

### Phase 2 — RC-4 `--collect-only -q` parsing

Unchanged from Rev 1: drop `-q` so output uses full `<file>::<test>` nodeids.
Note this test only runs under `CI=true`, so it must be verified with CI set.
Confirm installed pytest still emits the diagnosed `-q` format (or adjust the
parser) — see §4.

### Phase 3 — verification (the part Rev 1 omitted)

Rev 1's Phase 3 was "full suite verification." That is insufficient here, because
the failure mode under discussion **produces a green suite**. Verify instead:

1. **Run twice — with and without `CI=true`.** Capture both full summaries
   (not just a verbal recount).
2. **Assert the skip count changes.** After Phase 0, CI-unset must show the
   gated checks as `s`, not `.`. If passed-count is identical in both runs, the
   gates are being neutralized — that is the regression signal.
3. **Clear the March-named failures by name**, not by aggregate count. Do **not**
   bet on “998 → 1025”; re-observe live counts after the baseline re-run.
4. Re-run the collection gate under `CI=true` specifically (Phase 2's test).

---

## 4. Named unknowns — do not close these silently

- **RC-1f is unresolved in Rev 1** — it says "Investigation needed" about whether
  `--out artifacts/snapshot.json` resolves against `target/artifacts/` or `cwd`.
  That question is still open. Resolve it before assuming the fixture fixes those
  two tests; they may need the path-base fix instead.
- **4.7-month staleness** — the recorded run predates any dependency movement
  since 2026-03-01. Re-run before executing; failures beyond the 27 are unaudited.
- **pytest version drift** — RC-4 was diagnosed against pytest 9.0.2's `-q`
  format. Confirm the installed version still behaves that way, or the fix targets
  a format that has since changed again.
- **Live failure set / Phase 1 clear-count** — 26 is Rev 1 arithmetic against March;
  treat as hypothesis until re-observed.

---

## 5. Revised effort

| Phase | Work | Fixes |
|---|---|---|
| 0 | Forged-green `return` → `skip`; four downgrade paths → visible skip; leave `test_ci_env_contracts` | 0 (makes disablement auditable) |
| 1 | opt-in fixture + explicit application | *hypothesis:* most of RC-1/2/3; not a guaranteed 26 |
| 2 | `-q` parsing in collection gate | 1 (when CI set) |
| 3 | dual-run verification (CI set / unset); skip-count must move | — |

**Confidence split:** high on sequence and on what not to do; deliberately loose on
magnitudes until re-observed.

**Next concrete step:** Phase 0, then a baseline `pytest` with and without
`CI=true` — captured, not summarized. Do not implement the rest blind against
the March inventory.

---

## 7. Live dual-run baseline (2026-07-23, after Phase 0)

Captured under `artifacts/` (gitignored):

| Run | Result | Artifact |
|---|---|---|
| Phase 0 gates, no CI | 1 failed, 4 passed, **6 skipped** | `artifacts/phase0_gates_no_ci.txt` |
| Phase 0 gates, CI=true | 2 failed, 5 passed, **4 skipped** | `artifacts/phase0_gates_with_ci.txt` |
| Full suite, no CI | **23 failed**, 997 passed, **9 skipped** (480s) | `artifacts/baseline_no_ci.txt` |
| Full suite, CI=true + CONFIDENCE_ENTRYPOINTS | **32 failed**, 990 passed, **7 skipped** (523s) | `artifacts/baseline_with_ci.txt` |

**Phase 0 structural check:** skip count moved (9 → 7 full suite; 6 → 4 on
gate subset). Passed counts differ. Collection gate is SKIPPED without CI and
**runs** (currently fails — Phase 2 / real collection gaps) with CI. Absence
now has a signature.

**Phase 1 strategy correction from live evidence:** many RC-1 failures still
occur with ambient CI **unset**, because tests hardcode `env["CI"]="true"` and
pass absolute `--out` together with `--ci`. Example:
`tests/test_debt_snapshot_ci.py::_run`. The opt-in `clean_ci_env` fixture only
helps **ambient / in-process** leakage (e.g. `TestDebtCLI`). Tests that
deliberately set CI in the subprocess need **cwd + relative `--out`** (Rev 1
option A), not env scrubbing. Treat “26” as obsolete; clear by name from the
live lists above.

**Unaudited beyond March shape:** `test_confidence_policy_requires_signal_logic_bump`
(manifest drift), `test_contracts_bundle_is_fresh`, JS/TS parity failures,
collection-gate missing files — do not fold into the CI-env scrub.

---

## 8. Execution log (2026-07-23)

### Phase 0 — done (scope = early-exit sites only)
- Bare `return` → `pytest.skip` in collection gate
- Tagged-CI BOM early exits → `pytest.skip` (4 tests)
- OpenAPI missing-artifact soft exit → `pytest.skip`

**Correctly excluded from Phase 0 (not unfinished work):**
- `test_ci_env_contracts.py` — already `pytest.skip` when not CI; nothing to change
- `test_confidence_policy_requires_signal_logic_bump.py` and
  `test_confidence_golden_requires_confidence_version_bump.py` — **not
  early-exit sites.** `_require_entrypoints_in_ci()` is a conditional
  assertion that only tightens entrypoint mode under CI; the version-bump
  check still runs locally. There is no `return` to convert. Skipping them
  would disable real work.

### Phase 1 — done (corrected strategy)
Live evidence overturned “just scrub CI”:
- `--ci` **requires** `CI=true` (`contracts/ci_mode.py`)
- With both set, absolute `--out` is rejected; relative `--out` resolves against **scan root** and must stay under `artifacts/`

Applied:
- `tests/conftest.py` — opt-in `clean_ci_env` (not autouse)
- `TestDebtCLI` — `usefixtures("clean_ci_env")`
- Exceptions pipeline — strip ambient CI in subprocess env (no `--ci`)
- Debt/exit/parity tests — `CI=true` + relative `--out` under scan-root `artifacts/` (RC-1f resolved: was reading `cwd/artifacts` while CLI wrote `scan_root/artifacts`)

### Phase 3 dual-run after fixes

| Run | Result | Artifact |
|---|---|---|
| no CI | **5 failed**, 1015 passed, **9 skipped** | `artifacts/verify_no_ci.txt` |
| CI=true + CONFIDENCE_ENTRYPOINTS | **6 failed**, 1016 passed, **7 skipped** | `artifacts/verify_with_ci.txt` |

Skip count moves (9 → 7). Passed counts differ. Collection gate SKIPPED without CI, **runs** with CI.

Remaining failures (not CI-env scrub; separate work):
1. `test_confidence_policy_requires_signal_logic_bump` — manifest/hash drift
2. `test_contracts_bundle_is_fresh` — stale bundle
3. `test_api_cli_parity_ci` — CLI stdout not JSON (`NoneType`)
4–5. JS/TS parity (2)

**March 27 → live 5** (collection gate cleared in §9). Original RC-1/2/3 set cleared by name.

---

## 9. Phase 2 — collection gate instrument (2026-07-23)

**Why first:** its failure was ambiguous between “`-q` parser broken” and “gate
files produce zero tests.” Fix the instrument before reading it.

**What `-q` actually emits (pytest 9.0.1):** `tests/file.py: N` — no `::`.
The parser that required `::` therefore reported every gate as uncollected.

**Ground truth without `-q`:** the five named “missing” files all collect:

| File | Collected |
|---|---|
| `test_openapi_scrub_audit_baseline.py` | 1 |
| `test_openapi_scrub_baseline_requires_signal_logic_bump.py` | 1 |
| `test_openapi_scrub_budgets_requires_signal_logic_bump.py` | 1 |
| `test_openapi_golden_endpoints.py` | 3 |
| `test_golden_manifest_requires_signal_logic_bump.py` | 1 |

**Fix:** drop `-q` from the subprocess (`--collect-only` only). Verified under
`CI=true`: `test_dedicated_gate_files_are_collected_by_pytest_in_ci` **PASSED**.

**Verdict:** cosmetic / miscalibrated scanner — not a real uncollected-governance
finding. Gates you believed were running **are** being collected.

---

## 10. Sibling scan + triage of the remaining five (2026-07-23)

### 10.1 Sibling pytest-output parsers

Grep for `collect-only`, nodeid `::` scraping, and subprocess pytest parsing:

| Location | Parses pytest output? |
|---|---|
| `tests/test_contract_manifest_self_consistency.py` (Phase 2) | **Yes** — only sibling; fixed |
| `.github/workflows/*.yml` | No — invoke `pytest -q` only |
| `scripts/` | No matches |

No other pre-9 `-q` / nodeid scrapers found. Defect had no live relatives in-repo.

### 10.2 Drift family — stale artifact vs generator?

**`contracts_bundle` (rule_registry_schema):** neither. Bundle hash matches
`git show HEAD:schemas/rule_registry.schema.json` (LF). Working tree has CRLF
(`autocrlf`); `hash_scope: file_bytes` hashes the smudged bytes → mismatch.
Platform line-ending trap, not a real schema/generator change. Would likely be
green on LF CI. Fix direction: normalize newlines before hash (or force LF in
`.gitattributes` for hashed artifacts) — **not** blind regenerate on Windows.

**`confidence_policy` manifest:** generator/runtime, not intentional logic drift.
Closure paths unchanged. Hashing is AST-`dump`-based; live Python **3.14**
produces `efe0329…` while the manifest recorded under an older CPython is
`a2f6e0d…`. Same family as unpinned OpenAPI snapshot drift: the fingerprint
machine moved. Fix direction: stabilize the hash (pin Python for the gate, or
make normalization version-stable) — **not** a `signal_logic_version` bump
unless logic actually changed.

### 10.3 Parity family — one root, three faces

All three failures are **default positional** CLI with `encoding="utf-8"` and
`capture_output=True`. Scan-subcommand JS/TS tests **pass**.

Root: dashboard stderr contains a Windows-1252 byte (`0x97`, en-dash in
"fix before shipping—…"). UTF-8 decode in the reader thread raises
`UnicodeDecodeError` → `stdout` becomes **`None`**. Not a missing JSON field;
the CLI path never delivers stdout to the test.

Evidence:
- `assert None == '{…api json…}'` (default JS/TS vs API)
- `json.loads(None)` (default vs scan; api_cli_parity)
- Repro: `encoding="utf-8"` → stdout `None`; `errors="replace"` → stdout OK
- Scan tests use `text=True` (locale/cp1252) → succeed on the same machine

### 10.4 Fix choices — not mechanical (decision bars)

**Parity — do not treat harness soften vs product fix as equivalents.**

| Option | Fixes | Risk |
|---|---|---|
| `errors="replace"` in tests | harness only | Masks a real Windows product defect if cp1252 consoles already lose/break stderr |
| Emit UTF-8 from CLI stderr | product | Correct if the CLI owns the encoding contract |
| **ASCII-only stderr** (replace en-dash/emoji in dashboard) | product | No config surface; typographic punctuation in diagnostics is a latent portability hazard — preferred third option |

Decide with: *does a real Windows user on a cp1252 console see broken/missing stderr?*
If yes, loosening the test decoder is the OpenAPI-regen-without-pin shape.
If proven harness-only, `errors="replace"` is fine — **record why** so it is not re-derived.

**Drift — don't regenerate.**

| Artifact | Prefer |
|---|---|
| `contracts_bundle` | `.gitattributes` LF for hashed artifacts (cause at checkout), not hash-function-only normalize |
| Confidence AST hash | Judgment: pin interpreter (local 3.14 can't run the gate) vs interpreter-independent fingerprint (may false-bump on whitespace). Pinning is the **same class of decision** as OpenAPI dep-pinning in CI-rot — make once, consistently |

---

## 11. Sequencing (corrected)

**Land remediation first** — Phase 0–2 + path/`artifacts/` fixes + opt-in
`conftest` + this Rev2 doc. Test-infrastructure only; dual-run verified; coherent
bounded slice. **Do not** bundle parity or drift into that PR (different kind of
change, different review bar; finished work must not sit at risk behind open
questions).

Then, as separate efforts:
1. Parity (product encoding / ASCII stderr — after the cp1252-user question)
2. Drift (`.gitattributes` + confidence fingerprint policy)
3. CI-rot resurrection (pin deps → regenerate OpenAPI → layer 6)

**What the exercise established:** Rev 1's "all 27 are environmental, not logic"
was true of the visible 27 and wrong about the suite. Behind the noise sat a real
encoding defect, a real hash-stability problem, and a real line-ending policy gap.
Clear the noise, then read what's underneath — only execution could show that.
