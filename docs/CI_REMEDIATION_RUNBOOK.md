# CI Remediation Runbook — landing sequence + governance

**Status as of 2026-07-25.** `main`'s `Run pytest (Python 3.11)` check is red. The
red is a *layered stack* masked by `--maxfail=1` (only the first failure shows).
This runbook records the fixes, the exact order to land them, and the governance
gate that stops the whole class from recurring. Companion: `docs/CI_RED_LAYERS_HANDOFF.md`.

---

## The recurrence had two engines — both now addressed

1. **Wrong instructions an automated agent obeyed.** The `copilot-swe-agent` bot
   repeatedly (a) bulk-synced `schemas/` → `src/code_audit/data/schemas/` and
   (b) fabricated `schema_version` consts on non-envelope schemas to force
   `test_schema_version_freeze` green. Both traced to *incorrect signals*:
   - `load.py`'s "canonical / match `schemas/`" comment → **fixed** (superset
     gate + corrected comment, PR #10).
   - `.github/copilot-instructions.md` line ~838 said "schemas use `schema_version`
     const" without noting non-envelope schemas don't → **fixed** (PR #10): now
     distinguishes envelope vs non-envelope and forbids fabricating the field.
2. **No gate to stop bad output landing.** `main` is **not branch-protected**
   (`gh api …/branches/main/protection` → 404). Nothing blocks a red or poisoned
   commit from reaching main. → **branch protection, applied after green (below).**

Two structural guards for the hash-drift class were also installed:
`scripts/_ci_guard.py` (Python-version axis) and `.gitattributes` (OS/line-ending
axis). Both context-ambiguities that let hashes drift are now pinned.

---

## The open PRs (the coordinated fix)

| PR | Branch | Fixes | Axis |
|----|--------|-------|------|
| #9 | `fix/bom-manifest-ast-drift` | `.gitattributes` keystone (LF everywhere) + CRLF manifest hashes + treesitter CI install + Layer-4b byte-hash manifests (golden, contracts_bundle). Bot poison `d7ee736` reverted (`0a5f1ee`). | CRLF / OS |
| #10 | `fix/schema-freeze-oversync` | Revert schema over-sync; make fallback-sync gate a **superset** check; `data/schemas/README.md`; corrected `copilot-instructions.md`. **Schema authority.** | schema model |
| #11 | `fix/js-ts-findings-parity` | Install `treesitter` extra so JS/TS analysis runs in CI. | dependency |
| #12 | `fix/ci-manifest-known-reds` | 6 AST-hash gates pinned to CI Python (`_ci_guard.py` + skip-off-3.11 + regen on 3.11). | Python-version |

---

## Landing sequence — STRICT ORDER

> Enabling branch protection *before* main is green blocks the very PRs that make
> it green. Protection goes on **last**.

1. **Pause the bot.** Stop assigning Copilot / `@copilot` to these branches. It is
   GitHub's server-side coding agent (committer `GitHub`, author
   `copilot-swe-agent[bot]`), **not** a repo workflow — it cannot be disabled by
   editing files. It runs when *someone assigns it a task*. Stop assigning it
   until #10 lands. This stops the next recurrence immediately.
2. **Merge #10** (schema authority) — resolves the freeze-vs-mirror contradiction
   correctly (envelope-only + superset gate). Everything schema-related defers to it.
3. **Reconcile & merge #9** — rebase on updated main; where #9 and #10 disagree on
   `src/code_audit/data/schemas/` contents, **#10's deletions win** (non-envelope
   schemas do not belong there). Brings the `.gitattributes` keystone to main.
4. **Regenerate Layer-4b manifests if needed** — with `.gitattributes` on main,
   `golden_fixtures_manifest.json` and `contracts_bundle.json` regenerate to stable
   LF hashes (see `CI_RED_LAYERS_HANDOFF.md` §4b). Byte-hash, no Python guard.
5. **Merge #11 and #12.**
6. **Verify main is green with the FULL suite, not maxfail-masked:**
   ```bash
   python -m pytest -o addopts="" -q    # collect-all; --maxfail=1 hides the stack
   ```
   Confirm zero failures on Python 3.11 (the CI interpreter). Windows-local devs:
   AST gates *skip* off 3.11 by design; byte-hash gates need an LF checkout
   (`.gitattributes` handles this once landed; set `core.autocrlf=false` if stale).
7. **Enable branch protection** (next section) — only now.

---

## Branch protection — apply AFTER step 6 (main green)

Pick required-check **names from a fresh, green PR run** (`gh pr checks <n>`), do
NOT invent them. A misnamed or path-filtered required check stays permanently
*pending* and blocks every merge. The required set must be gates that would have
*caught the bot's poison* — so a fabricated const fails the corrected freeze gate,
and a re-sync fails the superset gate, at the bot's own PR.

```bash
gh api -X PUT repos/HanzoRazer/code-analysis-tool/branches/main/protection \
  -H "Accept: application/vnd.github+json" --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Run pytest (Python 3.11)", "rule-registry-sync"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

- `strict: true` — up-to-date-before-merge. Kills the **stale-base** class (the
  #8-merged-red / manufactured-conflict pattern from this cascade).
- `dismiss_stale_reviews: true` — if the bot staples a commit after approval, the
  approval drops → poison can't ride in on a stale review.
- `enforce_admins: false` — lets an admin bypass to land emergency fixes; the
  required checks still gate normal PRs (incl. the bot's).
- `required_pull_request_reviews` — the bot cannot self-merge; a human must approve.

Confirm the `contexts` names match the actual checks: `gh pr checks <a-green-PR>`.
The pytest job here is named **`Run pytest (Python 3.11)`** and the other check is
**`rule-registry-sync`** — verify these are still the emitted names before applying.

---

## What "green" now means

With the corrected gates required, `green` means *"the bot could not fake it"* —
a fabricated `schema_version` fails the freeze gate, a re-synced `data/schemas/`
fails the superset gate, a CRLF-baked hash fails on LF CI, a 3.14-baked AST hash
is refused at generation. A dishonest green is now structurally harder than an
honest fix. That is the end state: the bot stops being *told* to do wrong
(instructions), stops being *invited* to run (don't assign it), and stops being
*able* to land bad commits (branch protection) — all three axes closed.
