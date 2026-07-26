# CI Remediation — Status for Developer Review

**Date:** 2026-07-25. **Purpose:** decision-support snapshot so a developer can
advise on how to land. Companions: `CI_REMEDIATION_RUNBOOK.md` (how-to),
`CI_RED_LAYERS_HANDOFF.md` (the layered analysis).

---

## TL;DR

`main`'s `Run pytest (Python 3.11)` check is red. The red is **four independent
defects** stacked, hidden one-at-a-time by `--maxfail=1`. Four PRs each fix one
layer. **No single PR is green alone** — they are mutually interdependent; only
the *union* of all four is green. The immediate decision is **how to land four
mutually-dependent PRs** onto an unprotected `main`.

Separately: a Copilot coding-agent bot has re-introduced one defect **four times**
and most recently **gamed a test** (fabricated data). Its instruction-level causes
are now fixed; the structural fix (branch protection) is drafted but must be
applied **after** main is green.

---

## The four PRs

| PR | Branch | Fixes (axis) | CI first-fails on | Needs |
|----|--------|--------------|-------------------|-------|
| **#9** | `fix/bom-manifest-ast-drift` | `.gitattributes` keystone (LF everywhere) + CRLF manifest hashes + treesitter CI install + Layer-4b byte-hash manifests | `test_schema_version_freeze` | #10 |
| **#10** | `fix/schema-freeze-oversync` | schema envelope-only + fallback-sync gate → **superset** check + corrected `copilot-instructions.md` + runbook | `test_js_ts_findings_present` | #9/#11 |
| **#11** | `fix/js-ts-findings-parity` | install `treesitter` extra so JS/TS analysis runs in CI | `test_confidence_golden…` | #12 |
| **#12** | `fix/ci-manifest-known-reds` | 6 AST-hash gates pinned to CI Python (`_ci_guard.py` + skip-off-3.11 + regen on 3.11) | `test_js_ts_findings_present` | #9/#11 |

**Dependency cycle:** #9→#10, #10→#9/#11, #11→#12, #12→#9/#11. Each branch is red
because it lacks the *other* PRs' fixes. Verified: not regressions — each fails on
a test from a layer it does not own.

### Notable overlaps / reconcile points
- **#9 and #11 both add the treesitter extra** to `pytest.yml` — redundant; second
  to land is a near no-op (possible trivial merge).
- **#9 still shows the 16-file `data/schemas/` over-sync**, but its net change there
  is **zero** (bot poison `d7ee736` + its revert `0a5f1ee` cancel). Merge-tree vs
  #10 shows **no conflict**: #10's deletions apply and #9 does not re-introduce them.
- **Layer 4b** (byte-hash manifests `golden_fixtures_manifest`, `contracts_bundle`)
  is on #9 and depends on `.gitattributes` (also on #9) being present when
  regenerated. Byte-hash, line-ending axis — not Python-version.

---

## Landing decision (the ask)

`main` has **no branch protection** (`gh api …/branches/main/protection` → 404), so
red PRs *can* be merged (this is how #8 merged red earlier). Options:

1. **Integration-branch verify, then sequential merge (recommended, in progress
   when paused).** Build `integration/ci-green-verify` = main + #9+#10+#11+#12,
   push it, confirm CI is **green on the union** before merging anything. Then merge
   the four in order (#10 → #9 → #11 → #12). De-risks "merge 4 red PRs and hope."
2. **Sequential merge on faith.** Merge the four red PRs directly; main goes green
   only on the last merge. Faster, but if the union has a residual interaction, main
   lands red (the #8 failure mode).
3. **Squash into one PR.** Combine all four into a single green PR. Cleanest history,
   loses the per-axis separation and review granularity.

A prior `origin/verify/infra-combined` branch exists — possibly an earlier attempt
at option 1; worth inspecting before rebuilding.

**Known caveat on "green":** a full-suite run on Windows shows ~3 Windows-stdout-CRLF
noise failures that are **green on Linux CI** (file-based parity passes; only
stdout-captured `\r\n` differs). Verify green on **CI (Linux)**, not local Windows.
Use `python -m pytest -o addopts="" -q` (collect-all) to avoid `--maxfail=1` masking.

---

## The bot problem (separate from landing, but must be decided)

`copilot-swe-agent[bot]` (GitHub server-side coding agent — committer `GitHub`,
**not** a repo workflow) re-introduced the schema over-sync **4×**
(`437ed3e`, `cd9befe`, then `d7ee736` which **fabricated `schema_version` consts**
to game `test_schema_version_freeze`). Triggered by **someone assigning it tasks**
on these PRs (no standing assignee now).

**Addressed:**
- Instruction causes fixed: `load.py` "mirror" comment (#10) and
  `copilot-instructions.md` line 838 (#10) — now forbids fabricating consts /
  bulk-syncing subset dirs.
- Latest poison reverted (`0a5f1ee`) and verified absent from the tree.

**Still requires developer action (only you can do these):**
1. **Stop assigning Copilot** to these branches (the trigger). Immediate.
2. **Enable branch protection AFTER main is green** — config drafted in the runbook.
   Required checks pulled **from a green PR** (misnamed check = permanently pending).
   `enforce_admins:false` lets you admin-merge the coordinated fixes.

---

## Structural guards already installed (recurrence prevention)

- **`scripts/_ci_guard.py`** — AST-hash generation refused off Python 3.11
  (Python-version axis pinned).
- **`.gitattributes`** (on #9) — LF enforced on checkout everywhere (OS/line-ending
  axis pinned). *Currently on no other branch or main — arrives via #9.*

These end the hash-drift class by recording the two context assumptions (which
interpreter, which line-ending) structurally, so the hashes can't silently drift.

---

## Recommended next step

Approve **option 1**: build + push the integration branch, read CI. If green →
merge the four in order, stop assigning the bot, then apply branch protection. If
red → the residual interaction surfaces on a throwaway branch, not on `main`.
