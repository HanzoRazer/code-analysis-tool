from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DIR = REPO_ROOT / "tests" / "fixtures" / "expected"
CONTRACTS_DIR = REPO_ROOT / "tests" / "contracts"
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

    # ── Confidence golden fixture integrity check ────────────────
    confidence_dir = REPO_ROOT / "tests" / "fixtures" / "confidence"
    cases_path = confidence_dir / "cases.json"
    confidence_expected_dir = confidence_dir / "expected"

    if cases_path.exists():
        # cases.json exists → expected/ dir and per-case files MUST exist
        if not confidence_expected_dir.exists():
            raise SystemExit(
                "Confidence golden contract incomplete:\n"
                "  cases.json exists but expected/ directory is missing.\n"
                "Run: python scripts/refresh_golden_confidence.py\n"
            )

        # Load and validate cases.json
        try:
            cases_data = json.loads(cases_path.read_bytes())
        except Exception as e:
            raise SystemExit(f"Invalid JSON in cases.json: {e}")

        case_names = [c["name"] for c in cases_data.get("cases", [])]
        if not case_names:
            raise SystemExit(
                "cases.json contains no cases — cannot build golden contract.\n"
                "Add at least one case or remove the file.\n"
            )

        # Every case must have a corresponding expected file
        for name in case_names:
            expected_file = confidence_expected_dir / f"{name}.json"
            if not expected_file.exists():
                raise SystemExit(
                    f"Confidence golden contract incomplete:\n"
                    f"  Case {name!r} in cases.json has no expected file:\n"
                    f"    {expected_file.relative_to(REPO_ROOT)}\n"
                    f"Run: python scripts/refresh_golden_confidence.py\n"
                )

            # Validate each expected file structure
            try:
                payload = json.loads(expected_file.read_bytes())
            except Exception as e:
                raise SystemExit(
                    f"Invalid JSON in {expected_file.relative_to(REPO_ROOT)}: {e}"
                )

            score = payload.get("expected_score")
            if score is None:
                raise SystemExit(
                    f"Confidence expected file has null expected_score:\n"
                    f"  {expected_file.relative_to(REPO_ROOT)}\n"
                    f"Run: python scripts/refresh_golden_confidence.py\n"
                )

            if not isinstance(score, int):
                raise SystemExit(
                    f"Confidence expected_score must be int, got {type(score).__name__}:\n"
                    f"  {expected_file.relative_to(REPO_ROOT)}\n"
                    f"Run: python scripts/refresh_golden_confidence.py\n"
                )

    # ── Hash golden fixture files ────────────────────────────────
    files = sorted(EXPECTED_DIR.glob("*.json"))
    mapping: dict[str, str] = {}
    for p in files:
        rel = p.relative_to(REPO_ROOT).as_posix()
        mapping[rel] = _sha256_file(p)

    # Include confidence golden fixtures in the manifest
    if cases_path.exists():
        # Hash cases.json itself
        rel = cases_path.relative_to(REPO_ROOT).as_posix()
        mapping[rel] = _sha256_file(cases_path)

        # Hash each per-case expected file
        for ef in sorted(confidence_expected_dir.glob("*.json")):
            rel = ef.relative_to(REPO_ROOT).as_posix()
            mapping[rel] = _sha256_file(ef)

    # ── Promoted contract artifacts (volatility governance) ──────
    # These semantic knobs define how golden fixtures are interpreted.
    # They are REQUIRED — if missing, the manifest is incomplete.
    #
    # NOTE: If you edit the promoted list, update:
    #   - tests/test_contract_manifest_self_consistency.py (PROMOTED_ARTIFACTS)
    promoted = [
        CONTRACTS_DIR / "openapi_scrub_audit_baseline.json",
        CONTRACTS_DIR / "openapi_scrub_budgets.json",
        CONTRACTS_DIR / "openapi_golden_scrub_policy.json",
        CONTRACTS_DIR / "openapi_golden_endpoints.json",
    ]

    missing = [p for p in promoted if not p.exists()]
    if missing:
        lines = [
            "Golden manifest promotion invariant violated:",
            "The following required contract artifacts are missing:",
        ]
        lines.extend([f"- {p.relative_to(REPO_ROOT)}" for p in missing])
        lines.append("")
        lines.append("These files define the OpenAPI contract interpretation surface and must exist.")
        raise SystemExit("\n".join(lines))

    for p in promoted:
        rel = p.relative_to(REPO_ROOT).as_posix()
        mapping[rel] = _sha256_file(p)

    payload = {
        "signal_logic_version": _find_signal_logic_version(),
        "files": mapping,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(mapping)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
