# `data/schemas/` — bundled runtime schemas (envelope-only)

**Do not bulk-sync this directory to match the repo-root `schemas/` directory.**

This directory is a deliberate **subset**, not a mirror. It contains only the
**versioned-envelope schemas** the package validates against at runtime — the
ones whose instances carry a `schema_version` discriminator:

- `run_result.schema.json`
- `signals_latest.schema.json`
- `debt_snapshot.schema.json`
- `user_event.schema.json`
- `rule_registry.schema.json`

(plus their `*.example.json` fixtures.)

## The invariant

`tests/test_schema_version_freeze.py` globs every `*.schema.json` here and
requires each to declare `properties.schema_version.const` matching
`[a-z0-9_]+_v[0-9]+`. **Non-envelope schemas** — `release_bom`, `finding`,
`release_gate_envelope`, `contracts_versions`, `schema_graph_bundle`,
`rules_registry`, the `openapi_*` and `release_*` gate-result schemas — have no
such field and therefore **must not live here**. Adding them turns the freeze
gate red.

## Why the full set is NOT copied here

The loader (`src/code_audit/contracts/load.py`) resolves any schema **not**
bundled here by falling through to repo-root `schemas/` (resolution priority
\#3). So the complete schema set is always reachable; bundling only the envelope
subset is intentional and sufficient. Copying the rest in is redundant *and*
breaks the freeze invariant.

## History

This directory was bulk-synced from `schemas/` twice by an automated agent
(commits `437ed3e`, `cd9befe`, both reading load.py's former "canonical" /
"match schemas/" comments as an instruction to mirror). Both were reverted. The
loader comments and this file exist to stop a third recurrence. If a schema
genuinely needs to be bundled for runtime, add it **individually** with a
`schema_version.const`, in its own reviewed change — never as a bulk sync.
