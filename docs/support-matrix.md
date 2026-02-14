# Support Matrix

This document defines what is **Supported** vs **Experimental** for v1.

## Definitions

### Supported

A command is **Supported** if it meets all of the following:

1. Supports `--ci/--deterministic` for stable, reproducible output.
2. Has tests that cover primary behavior.
3. Help text documents the command contract.
4. Exit codes are stable and follow the global contract:
   - `0` success
   - `1` policy/ratchet violation
   - `2` usage/runtime error
5. Output is suitable for CI (no prompts; JSON to stdout when requested).

Supported commands may be used as CI gates.

### Experimental

Commands marked **Experimental** are available and tested, but their output shape,
heuristics, and formatting may change without being treated as a breaking change.
They must not be used as a hard CI gate unless explicitly promoted to Supported.

## v1 Support Status

### Supported

- Default scan: `code-audit <path>`
- `scan`
- `validate`
- `fence list`
- `fence check`
- `governance deprecation`
- `governance import-ban`
- `governance legacy-usage`
- `debt scan`
- `debt snapshot` (**Baseline Source**)
- `debt compare` (**Ratchet Gate**)

### Experimental

- `debt plan`
- `report`
- `export`
- `dashboard`
- `inventory`
- `sdk-boundary`
- `truth-map`
- `trend`
- `predict`
- `cluster`
