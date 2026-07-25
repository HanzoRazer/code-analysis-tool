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

## Non-envelope schemas live only in repo-root `schemas/`

Schemas without a `schema_version` envelope — `release_bom`, `finding`,
`release_gate_envelope`, the `openapi_*`/`release_*` gate-result schemas,
`schema_graph_bundle`, `rules_registry`, `contracts_versions` — are used only by
build/release **scripts** (`scripts/generate_release_bom.py`,
`scripts/validate_*.py`, `src/code_audit/contracts/validate.py`) that read
repo-root `schemas/` directly in a repo checkout. They are **not** loaded via
this bundled dir at runtime, so they are intentionally absent here. Repo-root
`schemas/` is therefore a **superset** of this directory.

## History — the real root cause

This directory was bulk-synced from `schemas/` twice by an automated agent
(commits `437ed3e`, `cd9befe`). The true trigger was a **contradiction between
two CI gates**, not just a stale comment:

- `ci/enforce_fallback_schema_sync.sh` formerly required the two dirs to have
  **identical** file sets (full mirror).
- `tests/test_schema_version_freeze.py` requires this dir to be **envelope-only**.

Repo-root `schemas/` holds non-envelope schemas, so the two gates were
mutually unsatisfiable — and the mirror gate had been red on main since the dirs
diverged. The bot kept "fixing" the red mirror gate by syncing, which broke
freeze; reverting the sync fixed freeze but re-broke the mirror gate. The fix
(PR #10) made the mirror gate a **superset** check (canonical ⊆ fallback,
overlaps must match byte-for-byte) so both gates are consistent and the bot has
no failing gate to chase. If a schema genuinely needs runtime bundling, add it
**individually** with a `schema_version.const`, in its own reviewed change —
never as a bulk sync.
