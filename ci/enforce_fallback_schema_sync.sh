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

canonical_files="$(cd "$CANONICAL" && find . -type f -name '*.json' | sort)"
fallback_files="$(cd "$FALLBACK" && find . -type f -name '*.json' | sort)"

if [[ "$canonical_files" != "$fallback_files" ]]; then
  echo "ERROR: File sets differ between canonical and fallback schemas."
  echo "Canonical:"
  echo "$canonical_files"
  echo "Fallback:"
  echo "$fallback_files"
  exit 1
fi

while IFS= read -r file; do
  if ! cmp -s "$CANONICAL/$file" "$FALLBACK/$file"; then
    echo "ERROR: Schema file differs: $file"
    exit 1
  fi
done <<< "$canonical_files"

echo "Fallback schemas/ matches canonical."
