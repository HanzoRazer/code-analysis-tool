#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROTATION_PATH = Path(".github/oncall_rotation.json")
MANIFEST_PATH = Path(".github/oncall_rotation.manifest.json")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if not ROTATION_PATH.exists():
        raise SystemExit(f"Missing {ROTATION_PATH}")

    manifest = {
        "schema": "oncall_rotation_manifest_v1",
        "tracked_file": str(ROTATION_PATH),
        "sha256": sha256_file(ROTATION_PATH),
    }

    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {MANIFEST_PATH} sha256={manifest['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
