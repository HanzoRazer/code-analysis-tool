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


def die(msg: str) -> int:
    print(msg)
    return 1


def main() -> int:
    if not SCHEMA_PATH.exists():
        return die(f"Missing {SCHEMA_PATH}")
    if not MANIFEST_PATH.exists():
        return die(f"Missing {MANIFEST_PATH} (run scripts/refresh_oncall_rotation_schema_manifest.py)")

    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        return die(f"Invalid JSON in {SCHEMA_PATH}: {e}")

    schema_version = schema.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version.strip():
        return die("Schema must contain non-empty string: schema_version")
    if not VERSION_RE.match(schema_version.strip()):
        return die(f"Invalid schema_version '{schema_version}'. Must match ^oncall_rotation_schema_v\\d+$")

    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        return die(f"Invalid JSON in {MANIFEST_PATH}: {e}")

    if manifest.get("schema_version") != schema_version:
        return die(
            "Schema version mismatch.\n"
            f"schema.schema_version={schema_version}\n"
            f"manifest.schema_version={manifest.get('schema_version')}\n"
            "Fix: bump schema_version in schema and run scripts/refresh_oncall_rotation_schema_manifest.py"
        )

    expected = manifest.get("sha256")
    actual = sha256_file(SCHEMA_PATH)
    if expected != actual:
        return die(
            "Schema changed without refreshing schema manifest.\n"
            f"Expected sha256={expected}\n"
            f"Actual   sha256={actual}\n"
            "Fix: bump schema_version in schema and run scripts/refresh_oncall_rotation_schema_manifest.py"
        )

    print("oncall rotation schema manifest OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
