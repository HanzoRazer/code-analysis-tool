#!/usr/bin/env bash
# ci/enforce_fallback_schema_sync.sh
# Guards against a STALE fallback copy: for every schema BUNDLED at runtime
# (canonical = src/code_audit/data/schemas), repo-root schemas/ must contain a
# byte-identical copy.
#
# canonical is a deliberate SUBSET (the versioned-envelope schemas the package
# loads at runtime — see src/code_audit/data/schemas/README.md and
# tests/test_schema_version_freeze.py). Repo-root schemas/ is the FULL set and
# legitimately carries extra, non-bundled schemas (release_bom, finding, the
# release/gate-result schemas) used only by build/release scripts that read
# schemas/ directly. So this is a SUPERSET check (canonical ⊆ fallback), not a
# set-equality check. A prior equality check demanded a full mirror, which
# contradicted the envelope-only freeze invariant and drove repeated bulk-sync
# regressions (bot commits 437ed3e, cd9befe).
set -euo pipefail

CANONICAL="src/code_audit/data/schemas"
FALLBACK="schemas"

if [[ -d "$FALLBACK" && ! -d "$CANONICAL" ]]; then
  echo "ERROR: repo-root schemas/ exists but canonical schemas directory is missing: $CANONICAL"
  echo "This indicates a corrupted checkout or incorrect repo layout."
  exit 1
fi

if [[ ! -d "$FALLBACK" ]]; then
  echo "No repo-root schemas/ directory present — skipping fallback sync check."
  exit 0
fi

echo "Checking each bundled (canonical) schema has a matching copy in fallback schemas/"

canonical_files="$(cd "$CANONICAL" && find . -type f -name '*.json' | sort)"

missing=0
differ=0
while IFS= read -r file; do
  [[ -z "$file" ]] && continue
  if [[ ! -f "$FALLBACK/$file" ]]; then
    echo "ERROR: bundled schema missing from repo-root fallback: $file"
    missing=1
    continue
  fi
  if ! cmp -s "$CANONICAL/$file" "$FALLBACK/$file"; then
    echo "ERROR: Schema file differs (fallback is stale): $file"
    differ=1
  fi
done <<< "$canonical_files"

if [[ "$missing" -ne 0 || "$differ" -ne 0 ]]; then
  exit 1
fi

echo "OK: every bundled schema has a byte-identical copy in fallback schemas/ (extras in fallback allowed)."
