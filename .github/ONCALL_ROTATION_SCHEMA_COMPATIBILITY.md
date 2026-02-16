# Oncall Rotation Schema Compatibility Policy

This repository treats `.github/oncall_rotation.schema.json` as a **contract** for operator automation.
Any change to the schema affects CI behavior and oncall assignment.

## Definitions

- **Schema file:** `.github/oncall_rotation.schema.json`
- **Schema version:** the `schema_version` field inside the schema file.
  - Format is strictly: `oncall_rotation_schema_v<N>` (example: `oncall_rotation_schema_v1`)
- **Rotation file:** `.github/oncall_rotation.json`
- **Schema manifest:** `.github/oncall_rotation.schema.manifest.json` (pins `schema_version` + sha256)

## Versioning Rules

### v1 (stable)

`oncall_rotation_schema_v1` is considered **stable** for consumers within this repo:
- Additive, backwards-compatible changes **may** be made without breaking existing rotation files, but
  the schema must still be updated intentionally and the manifest refreshed.
- Examples of additive changes:
  - Add an optional field with a default
  - Add an optional label name
  - Add a new exception metadata field that does not affect selection semantics

### v2+ (breaking)

Bump to `oncall_rotation_schema_v2` (or higher) for any change that can break existing rotation files or tooling:
- Making a previously-optional field required
- Tightening constraints (e.g., new regex, new min/max)
- Changing or removing allowed values/enums
- Changing selection semantics that are represented by schema (e.g., new strategy meaning)

## Required Process for Schema Changes

When modifying `.github/oncall_rotation.schema.json`:
1. Decide whether this is backwards-compatible (stay on current vN) or breaking (bump to vN+1).
2. Update `schema_version` accordingly.
3. Refresh the schema manifest:
   ```bash
   python scripts/refresh_oncall_rotation_schema_manifest.py
   ```
4. Commit both:
   - `.github/oncall_rotation.schema.json`
   - `.github/oncall_rotation.schema.manifest.json`

CI enforces that:
- `schema_version` matches the naming contract
- the schema manifest matches the schema file contents and version

## Notes

This policy is intentionally conservative: schema changes must be explicit and auditable.
