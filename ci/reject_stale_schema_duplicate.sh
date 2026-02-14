#!/usr/bin/env bash
# ci/reject_stale_schema_duplicate.sh
# Fails if the known-stale duplicate schema dir exists.
set -euo pipefail

if [[ -d "code_audit/data/schemas" ]]; then
  echo "ERROR: stale duplicate directory exists: code_audit/data/schemas"
  echo "Delete it (canonical is src/code_audit/data/schemas)."
  exit 1
fi

echo "OK: no stale schema duplicate."
