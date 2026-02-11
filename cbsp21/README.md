# CBSP21 Governance Pack — code-analysis-tool

This folder contains the governance "patch manifest" artifacts used to describe, review, and verify changes to the **code-analysis-tool** repository.

## What's in here

- `patch_input.schema.json` — JSON Schema for the patch manifest (v1).
- `patch_input.json.example` — Example manifest tailored to this repo's layout and typical changes.
- `patch_input.template.json` — Minimal fill-in template for new patches.

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
