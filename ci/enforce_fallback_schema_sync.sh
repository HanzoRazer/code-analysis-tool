#!/usr/bin/env bash
# ci/enforce_fallback_schema_sync.sh
# Fails if repo-root schemas/ exists but diverges from canonical.
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

echo "Checking fallback schemas/ against canonical $CANONICAL"

canonical_list="$(mktemp)"
fallback_list="$(mktemp)"
trap 'rm -f "$canonical_list" "$fallback_list"' EXIT

(cd "$CANONICAL" && find . -type f -name '*.json' | sort > "$canonical_list")
(cd "$FALLBACK" && find . -type f -name '*.json' | sort > "$fallback_list")

canonical_files="$(cat "$canonical_list")"
missing_in_fallback="$(comm -23 "$canonical_list" "$fallback_list")"
if [[ -n "$missing_in_fallback" ]]; then
  echo "ERROR: Fallback schemas/ is missing canonical files:"
  echo "$missing_in_fallback"
  exit 1
fi

while IFS= read -r file; do
  if ! cmp -s "$CANONICAL/$file" "$FALLBACK/$file"; then
    echo "ERROR: Schema file differs: $file"
    exit 1
  fi
done <<< "$canonical_files"

echo "Fallback schemas/ matches canonical."
