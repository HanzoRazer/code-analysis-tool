from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DIR = REPO_ROOT / "tests" / "fixtures" / "expected"
OUT = REPO_ROOT / "tests" / "contracts" / "golden_fixtures_manifest.json"
SRC = REPO_ROOT / "src"


def _read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def _find_signal_logic_version() -> str:
    candidates = [
        SRC / "code_audit" / "model" / "run_result.py",
        SRC / "code_audit" / "run_result.py",
    ]
    for p in candidates:
        if not p.exists():
            continue
        s = _read_text(p)
        m = re.search(r"signal_logic_version[^=\n]*=\s*[\"']([^\"']+)[\"']", s)
        if m:
            return m.group(1)
    raise SystemExit("error: could not locate signal_logic_version default")


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return f"sha256:{h.hexdigest()}"


def main() -> int:
    if not EXPECTED_DIR.exists():
        raise SystemExit(f"error: missing expected dir: {EXPECTED_DIR}")

    files = sorted(EXPECTED_DIR.glob("*.json"))
    mapping: dict[str, str] = {}
    for p in files:
        rel = p.relative_to(REPO_ROOT).as_posix()
        mapping[rel] = _sha256_file(p)

    payload = {
        "signal_logic_version": _find_signal_logic_version(),
        "files": mapping,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
