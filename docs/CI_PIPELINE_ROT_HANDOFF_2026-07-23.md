# Engineer Handoff — CI Pipeline Rot (PR-gate resurrection)

**Date:** 2026-07-23
**Repo:** `github.com/HanzoRazer/code-analysis-tool`
**Base branch:** `main`
**HEAD at diagnosis:** `2309fb1`
**Status:** 🔴 **UNRESOLVED — hand off as a dedicated effort.** Nothing here is fixed on `main`.
**Trigger:** two docs-only PRs (#2, #3) could not merge because both required PR checks
(`Run pytest (Python 3.11)` and `rule-registry-sync`) fail — on **every** PR, for reasons
unrelated to the PR contents.

---

## 0. TL;DR / annotation for whoever picks this up

The two red PR checks are **not two bugs** — they are the visible top of a **multi-layer
chain of pre-existing CI rot**. Each fix only exposes the next layer. Attempting a quick
gate fix (PRs #4, #5, #6 — now **closed as dirty**) peeled back **five** layers and reached
a sixth (the full test suite) that was never even executed. This needs to be resolved
**holistically as one deliberate CI-resurrection task**, not incrementally, and it involves
**judgment calls** (adding an undeclared dependency, regenerating a committed artifact,
possibly fixing real test failures) that were deliberately **not** made here.

**Do not** merge partial dependency/schema fixes one at a time — the checks stay red until
the *whole* chain is green, so partial PRs are pure noise (that is exactly why #4/#5/#6
were closed).

---

## 1. The failure chain (peel order)

Each row is a distinct root cause. Fixing row *N* reveals row *N+1*.

| # | Layer | Symptom (observed in CI) | What it actually needs |
|---|-------|--------------------------|------------------------|
| 1 | **Schema drift** | `ci/enforce_fallback_schema_sync.sh`: *"File sets differ between canonical and fallback schemas"* — canonical `src/code_audit/data/schemas/` had **9** files, repo-root fallback `schemas/` had **21** | Reconcile the two dirs (see §3 — promote, don't trim) |
| 2 | **`rule-registry` never installs pytest** | `python: No module named pytest` — the *"Enforce PUBLIC_RULE_IDS ↔ registry contract gate"* step ran `pip install -e .` (no test deps) then `python -m pytest …` | Install a test extra before invoking pytest |
| 3 | **`fastapi` missing** | `ModuleNotFoundError: No module named 'fastapi'` — pytest imports *every* test module during collection; `tests/test_openapi_diff_core.py` → `src/code_audit/web_api/main.py` → `from fastapi import FastAPI`. Also hit by pytest.yml's *"Check OpenAPI snapshot freshness"* step | Install the `api` extra (`fastapi`, `uvicorn`, `pydantic`) in **both** workflows |
| 4 | **`httpx` undeclared** ⚠️ | `RuntimeError: The starlette.testclient module requires the httpx … package` collecting `tests/web_api/test_endpoints.py` | **`httpx` is NOT in any extra in `pyproject.toml`.** Must be *added* as a new dependency — this is a dependency-management decision, not an install-flag change |
| 5 | **Stale committed OpenAPI snapshot** ⚠️ | `refresh_openapi_snapshot.py`: *"OpenAPI snapshot is stale."* The tracked `docs/openapi.json` no longer matches what the app generates | Regenerate & commit `docs/openapi.json` (`python scripts/refresh_openapi_snapshot.py --write`) — **but** the drift is almost certainly caused by **unpinned** `fastapi`/`pydantic` (CI pulled `fastapi 9.x`); regenerating without pinning just moves the target |
| 6 | **Full `pytest -q` suite** ❓ | **Never reached** — job dies at layer 4/5 first | Unknown. May contain real failures. Must be audited once layers 1–5 clear |

⚠️ = requires a judgment call (see §4). ❓ = completely unaudited.

---

## 2. Why the two checks are entangled

- **`rule-registry-sync`** blocks on layers 2 → 3 → 4 (its `pytest -k …` still collects the
  whole suite, so it inherits the web-api import chain).
- **`Run pytest (Python 3.11)`** blocks on layers 1 → 3 → 5 → 6.

They share layer 3 (`fastapi`). Neither can go green until its whole sub-chain is green.
Because `main` itself only runs the `contract-parity-main-observer` workflow (the pytest /
rule-registry workflows are `pull_request`-triggered), **this rot has never been visible on
`main`** — it only bites PRs, and likely has for a long time.

---

## 3. Known-good starting material (from the closed dirty PRs)

These diffs are **correct as far as they go** and verified to clear their specific layer;
they were closed only because they are partial. Re-derive or cherry-pick them into the
single resurrection PR. (Closed-PR diffs remain viewable on GitHub even after branch
deletion.)

### 3a. Layer 1 — schema promotion (was PR #4)
Non-destructive reconciliation. Canonical was a strict **subset** of the fallback (∅
canonical-only files; the 9 shared files already byte-identical), so **promote** the 12
fallback-only schemas into canonical — do **not** trim the fallback (that would delete real,
in-use schemas):

```
cp schemas/{contracts_versions.schema,drift_budget_signal.example,drift_budget_signal.schema,\
finding.schema,openapi_release_gate_result.schema,release_audit_failure.schema,release_bom.schema,\
release_bom_consistency_result.schema,release_bom_generator_gate_result.schema,\
release_gate_envelope.schema,rules_registry.schema,schema_graph_bundle.schema}.json \
   src/code_audit/data/schemas/
```
Verify: `bash ci/enforce_fallback_schema_sync.sh` → *"Fallback schemas/ matches canonical."*
(Note: also check `ci/enforce_schema_version_bump.sh` doesn't demand a version bump for the
added canonical files — it did **not** in testing, but confirm.)

### 3b. Layers 2+3 — install test + api extras (was PR #5)
In **both** `.github/workflows/rule-registry-sync.yml` and `.github/workflows/pytest.yml`,
change the install line:
```diff
- python -m pip install -e ".[dev]"
+ python -m pip install -e ".[dev,api]"
```
(and add `python -m pip install --upgrade pip` to rule-registry-sync.yml for parity.)

### 3c. What #6 was
`[VERIFY-ONLY]` throwaway branch (`verify/infra-combined`) merging #4+#5 to get a real
combined CI verdict. It is what exposed layers 4 and 5. Closed & deleted.

---

## 4. Judgment calls the resurrection must make (NOT made here)

1. **`httpx` dependency (layer 4).** It is undeclared. Decide: add it to the `dev` extra
   (test-only) or the `api` extra (runtime TestClient)? Pick a floor version. `starlette`'s
   TestClient needs it at test time, so `dev` is the likely home.
2. **OpenAPI snapshot (layer 5).** Regenerating `docs/openapi.json` is editing a committed,
   generated artifact. First decide whether the drift is a *real* API change or a
   *dependency-version* artifact. **Strongly recommend pinning `fastapi`/`pydantic`** (upper
   bounds) in the `api` extra before regenerating, so the snapshot is reproducible — otherwise
   this gate will rot again on the next fastapi release.
3. **Suite audit (layer 6).** Once 1–5 clear, run `pytest -q` and triage. There may be real
   failures. Budget for it; do not assume green.
4. **Should these gates run on `main` too?** They are PR-only today, which is how the rot went
   unnoticed. Consider adding `push: [main]` once green, so `main` can't silently re-rot.

---

## 5. Recommended remediation shape

Do it as **one** dedicated branch/PR titled e.g. `ci: resurrect PR-gate pipeline`, in this order:

1. Promote schemas (§3a).
2. Pin `fastapi`/`pydantic`, add `httpx`, then install `.[dev,api]` in both workflows (§3b, §4.1, §4.2).
3. Regenerate & commit `docs/openapi.json` with the pinned versions (§4.2).
4. Run the full suite locally with the pinned env; fix/triage whatever layer 6 surfaces (§4.3).
5. Only then is the PR green — verify against a real run before merging.
6. (Optional) add `push:[main]` triggers (§4.4).

**Acceptance:** both `Run pytest (Python 3.11)` and `rule-registry-sync` green on a single PR,
end-to-end, with no `--admin` override.

---

## 6. Cross-references

- **Blocked-by-this docs PRs (leave open):** #2 (incomplete-state-invariant note), #3
  (unverified-store-shape-predicate note). Both are one-file, docs-only, and orthogonal to
  this rot. Once the pipeline is green they pass on rebase; alternatively they may be
  `--admin`-merged independently since the failing gates are unrelated to their content.
- **Closed dirty PRs (diagnosis material only):** #4 (schema promote), #5 (dep install),
  #6 (verify-only combined). Branches deleted.
- **CI definitions:** `.github/workflows/pytest.yml`, `.github/workflows/rule-registry-sync.yml`,
  `ci/enforce_fallback_schema_sync.sh`, `scripts/refresh_openapi_snapshot.py`.
- **Dep declarations:** `pyproject.toml` → `[project.optional-dependencies]` (`dev`, `api`,
  `treesitter`, `all`). `httpx` absent.
