# CBSP21 Governance Pack — code-analysis-tool

This folder contains the governance "patch manifest" artifacts used to describe, review, and verify changes to the **code-analysis-tool** repository.

## What's in here

- `patch_input.schema.json` — JSON Schema for the patch manifest (v1).
- `patch_input.json.example` — Example manifest tailored to this repo's layout and typical changes.
- `patch_input.template.json` — Minimal fill-in template for new patches.
- `patch_input_v2.schema.json` — v2 schema (adds `scope.min_coverage_percent` + `diff_range.pinned_merge_base` for `pr_scope`).
- `patch_input_v2.template.json` / `patch_input_v2.example.json` — v2 fill-in + example.
- `pr_scope_acceptance.json` — Locked acceptance contract for the pr_scope detector.

## Enforcing scope with `pr_scope`

`pr_scope` is silent in ordinary scans. Pass a v2 manifest to activate it:

```
python -m code_audit scan . --pr-scope-manifest cbsp21/patch_input_v2.json
```

It then diffs `merge-base..HEAD` and reports:

- **contamination** (MEDIUM) — a changed file outside `scope.paths_in_scope` / `scope.files_expected_to_change`;
- **base drift** (HIGH) — only when `diff_range.pinned_merge_base` is set and differs from the merge-base computed from `diff_range.base`. Omit the field and no drift check runs;
- **coverage** (HIGH) — in-scope share of the diff, or the declared `file_context_coverage_percent`, below the threshold. `scope.min_coverage_percent` may raise the 95% contract floor but never lower it;
- **uncheckable** (CRITICAL) — missing/malformed/wrong-version manifest, shallow clone, unresolved merge-base, git failure or timeout. The check never fails quiet.

Because base drift needs a full merge-base, CI must check out with `fetch-depth: 0`; a shallow clone is reported as CRITICAL rather than passing.

## How to use

1. Copy `patch_input.template.json` to `patch_input.json` in your change branch.
2. Fill in the fields (especially `scope`, `diff_articulation`, and `verification`).
3. Run your normal verification steps and record them in `verification.commands_run`.
4. Reviewers validate: scope correctness, behavior/risk classification, and that verification evidence matches the diff.

## Notes for this repo (code-analysis-tool)

Common paths (adjust as needed):
- `src/` — core library code
- `tests/` — unit/integration tests
- `scripts/` — dev utilities
- `docs/` — documentation
- `i18n/` — canonical UI copy (JSON)
- `.github/` — CI workflows, PR template, copilot-instructions

`file_context_coverage_percent` is intended to capture how much of the relevant file(s) were reviewed (0–100).
