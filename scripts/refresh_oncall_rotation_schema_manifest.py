#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


SCHEMA_PATH = Path(".github/oncall_rotation.schema.json")
MANIFEST_PATH = Path(".github/oncall_rotation.schema.manifest.json")
VERSION_RE = re.compile(r"^oncall_rotation_schema_v\d+$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if not SCHEMA_PATH.exists():
        raise SystemExit(f"Missing {SCHEMA_PATH}")

    prior = {}
    if MANIFEST_PATH.exists():
        try:
            prior = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        except Exception:
            prior = {}

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema_version = schema.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise SystemExit("Schema must contain non-empty string: schema_version")
    if not VERSION_RE.match(schema_version.strip()):
        raise SystemExit(f"Invalid schema_version '{schema_version}'. Must match ^oncall_rotation_schema_v\\d+$")

    manifest = {
        "schema": "oncall_rotation_schema_manifest_v1",
        "tracked_file": str(SCHEMA_PATH),
        "schema_version": schema_version,
        # Preserve identity policy (defaults to stable if not present)
        "id_policy": prior.get("id_policy", "stable"),
        "stable_id": prior.get("stable_id", "oncall_rotation.schema.json"),
        "id_must_contain": prior.get("id_must_contain", None),
        "sha256": sha256_file(SCHEMA_PATH),
    }

    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {MANIFEST_PATH} version={schema_version} sha256={manifest['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
