## Description

<!-- What does this PR do? Keep it concise — one or two sentences. -->

## CBSP21 Patch Manifest

> **Every PR must include a completed patch manifest.**
> Copy [`cbsp21/patch_input.template.json`](../cbsp21/patch_input.template.json) to `patch_input.json` in your branch root, fill it in, and commit it with the PR.

- [ ] `patch_input.json` is included in this PR
- [ ] `patch_id` is unique (format: `CAT-NNNN`)
- [ ] `scope.paths_in_scope` and `files_expected_to_change` match the actual diff
- [ ] `change_type` is accurate (`code` · `docs` · `config` · `ci` · `refactor` · `test` · `security`)
- [ ] `behavior_change` is classified (`compatible` · `breaking` · `unknown`)
- [ ] `risk_level` is set (`low` · `medium` · `high`)
- [ ] `diff_articulation.what_changed` lists every meaningful change
- [ ] `diff_articulation.why_not_redundant` explains why this isn't duplicate work
- [ ] `verification.commands_run` lists the commands actually executed
- [ ] `file_context_coverage_percent` reflects how much of the touched files was reviewed

> Need a reference? See [`cbsp21/patch_input.json.example`](../cbsp21/patch_input.json.example) for a fully filled-out sample.
> Schema: [`cbsp21/patch_input.schema.json`](../cbsp21/patch_input.schema.json)

---

## Change Details

**Change type:** <!-- code / docs / config / ci / refactor / test / security -->
**Risk level:** <!-- low / medium / high -->
**Behavior change:** <!-- compatible / breaking / unknown -->

### What changed
<!-- Bullet list — mirrors diff_articulation.what_changed -->
-

### Why this isn't redundant
<!-- One sentence — mirrors diff_articulation.why_not_redundant -->

---

## Verification

- [ ] `python -m pytest -q` — all tests pass
- [ ] Copy lint passes (`python scripts/copy_lint.py`, `python scripts/copy_lint_vibe_saas.py`)
- [ ] Manual smoke test (describe below if applicable)

### Commands run
<!-- Mirrors verification.commands_run from your patch manifest -->
```
```

### Test results
<!-- Mirrors verification.test_results -->
```
```

---

## Reviewer Checklist

> Reviewers: use this checklist to validate the patch manifest against the actual diff.

- [ ] `patch_input.json` present and valid against [schema](../cbsp21/patch_input.schema.json)
- [ ] `changed_files_exact` matches the PR's file list
- [ ] `changed_files_count` matches the actual count
- [ ] `scope.paths_in_scope` is neither too broad nor too narrow
- [ ] `risk_level` is reasonable given the change
- [ ] Verification evidence is sufficient — commands were actually run
- [ ] `file_context_coverage_percent` is credible (≥ 80% for `medium`/`high` risk)
- [ ] No copy changes without copy lint passing
- [ ] No forbidden words in user-facing strings (see `copilot-instructions.md` § Copy lint rules)
