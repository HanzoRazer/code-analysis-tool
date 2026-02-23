# code_audit — Public Contract (v1.0.0)

This document defines the stability guarantees for version 1.x of `code_audit`.

Anything not described here is not a public contract.

---

## Release BOM (auditable semantic bill of materials)

Every tagged release publishes `dist/release_bom.json` as a release artifact.
This BOM is deterministic and self-describing, recording:

- `tool_version`, `engine_version`, `signal_logic_version`
- schema file hashes
- contract manifest hashes (golden fixtures, analyzer logic, translator policy, OpenAPI governance artifacts)
- Web API: OpenAPI snapshot hash, validator manifest, endpoint registry + schema
- git commit + tag

CI enforces:
- BOM can be generated deterministically
- BOM hashes match repo files
- tag `vX.Y.Z` matches `pyproject.toml` version `X.Y.Z` on tagged CI
- golden manifest includes promoted OpenAPI artifacts
- endpoint registry is schema-valid, sorted, unique, and matches OpenAPI snapshot

---

## 1. Supported Commands (v1 Stable Surface)

The following commands are considered **Supported v1** and are subject to stability guarantees:

- `code-audit <path>` (default scan)
- `scan`
- `validate`
- `fence list`
- `fence check`
- `governance deprecation`
- `governance import-ban`
- `governance legacy-usage`
- `debt scan`
- `debt snapshot`
- `debt compare`

All other commands are considered **Experimental** and may change behavior or output format without a major version bump.

---

## 2. Deterministic Mode Contract

All Supported v1 commands must support deterministic operation.

Deterministic mode is enabled via:

```
--ci
--deterministic
```

In deterministic mode:

- Timestamps are fixed to:
  `2000-01-01T00:00:00+00:00`
- Output ordering is stable and sorted
- JSON keys are sorted
- Paths are POSIX-normalized
- Randomness is seeded
- No environment-dependent metadata is included

Two identical runs against the same codebase must produce byte-identical JSON output.

---

## 3. Exit Code Contract

Supported v1 commands must follow this exit code contract:

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success (no violations or informational command completed) |
| 1 | Policy violation / ratchet failure |
| 2 | Usage error or runtime error |

No other exit codes are permitted for Supported v1 commands.

---

## 4. Baseline & Ratchet Contract

The canonical structural baseline is:

```
baselines/main.json
```

This file must conform to:

```
debt_snapshot_v1
```

CI ratchet rules:

- CI compares current deterministic snapshot against baseline
- CI fails if new structural debt is introduced
- CI never mutates baseline files
- Baseline updates must occur via explicit PR

---

## 5. Schema Stability

The following schemas are frozen under v1:

- `run_result_v1`
- `debt_snapshot_v1`

Breaking schema changes require:

- Incremented schema version
- Updated validation tests
- Updated golden fixtures
- Minor or major version bump

---

## 6. Versioning Rules

The following require version bump:

- Output shape change
- Schema change
- Severity mapping change
- Confidence scoring logic change
- Signal prioritization change

The following do NOT require version bump:

- Internal refactors
- Performance improvements
- Test additions
- Documentation updates
- Experimental command changes

---

## 7. Non-Goals of v1

- Automated code modification
- Autonomous refactoring
- Multi-language support
- Database persistence
- SaaS-specific logic

`code_audit` is a deterministic structural analysis engine.

---

## 8. API Stability

If programmatic APIs are introduced under:

```
code_audit.api
```

Those functions become part of the v1 stability surface and must follow semantic versioning.

---

## 9. Experimental Commands

The following commands are Experimental:

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

Experimental commands may change behavior or output without major version bump.

---

## 10. Guiding Principle

The purpose of `code_audit` is:

> Prevent structural decay while enabling fast iteration.

Stability, determinism, and clarity take precedence over feature expansion.

---

## 11. Confidence Policy Contract

Confidence scoring semantics are hash-guarded via **dependency-closure hashing**.

The confidence policy manifest hashes the dependency closure of the confidence
scoring entrypoints and all internal `code_audit.*` modules they import
(recursively), using AST normalization (strips docstrings and
`CONFIDENCE_POLICY_VERSION` assignments).

CI pins the hashing roots explicitly via:

```
CONFIDENCE_ENTRYPOINTS=src/code_audit/insights/confidence.py
```

If confidence scoring is refactored into new modules, update
`CONFIDENCE_ENTRYPOINTS` accordingly.

**Bump rules:**

- Editing confidence scoring logic (weights, thresholds, formula) → bump
  `signal_logic_version` + refresh manifest
- Adding new internal imports to the confidence module → refresh manifest
  (hash will change automatically via closure expansion)

**Refresh command:**

```bash
python scripts/refresh_confidence_policy_manifest.py
```
