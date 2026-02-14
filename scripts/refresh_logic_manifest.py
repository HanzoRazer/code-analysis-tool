from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure repo root is on sys.path so we can import from tests/.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# Import the helpers from the test module to keep one implementation of hashing.
# This is deliberate: the manifest generator and the enforcement test must match.
from tests.test_version_bump_enforcement import (  # type: ignore[import-untyped]
    _discover_analyzers,
    _find_signal_logic_version,
)

OUT = REPO_ROOT / "tests" / "contracts" / "logic_manifest.json"


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)

    analyzers = _discover_analyzers()
    payload = {
        "signal_logic_version": _find_signal_logic_version(),
        "analyzers": [
            {
                "module": a.module,
                "class_name": a.class_name,
                "version": a.version,
                "logic_hash": a.logic_hash,
            }
            for a in analyzers
        ],
    }

    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(analyzers)} analyzers)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
