#!/usr/bin/env bash
# ci/enforce_schema_version_bump.sh
# Fails if a canonical schema changed but schema_version.const was not bumped.
set -euo pipefail

BASE_REF="${GITHUB_BASE_REF:-main}"
git fetch origin "${BASE_REF}" --depth=1

changed="$(git diff --name-only "origin/${BASE_REF}...HEAD" || true)"
schema_changed="$(echo "$changed" | grep -E '^src/code_audit/data/schemas/.+\.schema\.json$' || true)"

if [[ -z "${schema_changed}" ]]; then
  echo "No canonical schema changes detected."
  exit 0
fi

echo "Canonical schema files changed:"
echo "${schema_changed}"

extract_const () {
  python - "$1" <<'PY'
import json, sys
p = sys.argv[1]
obj = json.load(sys.stdin)
const = obj.get("properties", {}).get("schema_version", {}).get("const")
print(const or "")
PY
}

while IFS= read -r f; do
  base_const=""
  if git cat-file -e "origin/${BASE_REF}:${f}" 2>/dev/null; then
    base_const="$(git show "origin/${BASE_REF}:${f}" | extract_const "${f}" || true)"
  fi

  head_const="$(cat "${f}" | extract_const "${f}" || true)"

  if [[ -z "${head_const}" ]]; then
    echo "ERROR: ${f} missing properties.schema_version.const"
    exit 1
  fi

  # If schema file existed before and changed now, const must bump.
  if [[ -n "${base_const}" && "${base_const}" == "${head_const}" ]]; then
    echo "ERROR: ${f} changed but schema_version.const did not bump (${head_const})."
    echo "       Bump properties.schema_version.const (e.g., *_v1 -> *_v2)."
    exit 1
  fi

  echo "OK: ${f} schema_version bumped (${base_const:-<new>} -> ${head_const})"
done <<< "${schema_changed}"
