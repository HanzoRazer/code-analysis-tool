"""Golden fixture tests — deterministic regression tests for signal_logic_version.

If this test fails due to an intended behavior change, bump ``signal_logic_version``
and regenerate the expected outputs:

    python -m pytest tests/test_golden_fixtures.py --golden-update

Or delete ``tests/fixtures/expected/`` and run the test to auto-generate.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from code_audit.analyzers.complexity import ComplexityAnalyzer
from code_audit.analyzers.dead_code import DeadCodeAnalyzer
from code_audit.analyzers.duplication import DuplicationAnalyzer
from code_audit.analyzers.exceptions import ExceptionsAnalyzer
from code_audit.analyzers.file_sizes import FileSizesAnalyzer
from code_audit.contracts.safety_fence import SafetyFenceAnalyzer
from code_audit.governance.import_ban import ImportBanAnalyzer
from code_audit.core.runner import run_scan

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "repos"
EXPECTED_DIR = Path(__file__).resolve().parent / "fixtures" / "expected"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "run_result.schema.json"

# Deterministic values for golden comparisons
_RUN_ID = "00000000-0000-0000-0000-000000000000"
_CREATED_AT = "2026-02-11T00:00:00+00:00"


def _golden_run(fixture_path: Path, tmp_path: Path) -> dict:
    """Run the class-based pipeline with deterministic hooks."""
    analyzers = [
        ComplexityAnalyzer(),
        DeadCodeAnalyzer(),
        DuplicationAnalyzer(),
        ExceptionsAnalyzer(),
        FileSizesAnalyzer(),
        ImportBanAnalyzer(),
        SafetyFenceAnalyzer(),
    ]
    result = run_scan(
        fixture_path,
        analyzers,
        project_id="",
        _run_id=_RUN_ID,
        _created_at=_CREATED_AT,
    )
    return result.to_dict()


def _normalize(d: dict) -> dict:
    """Normalize volatile fields so golden comparisons are semantic and cross-platform.

    Strips machine-dependent config.root and normalizes path separators.
    Also removes hash/ID fields that can differ across Python versions
    (e.g., AST dump hashing) while keeping messages, severities, locations,
    and counts intact.
    """
    out = json.loads(json.dumps(d, sort_keys=True, default=str))

    # 1) Drop machine-dependent config
    if "run" in out and "config" in out["run"]:
        out["run"]["config"].pop("root", None)

    # 2) Normalize path separators
    def _fix_paths(v):
        if isinstance(v, dict):
            return {k: _fix_paths(val) for k, val in v.items()}
        if isinstance(v, list):
            return [_fix_paths(x) for x in v]
        if isinstance(v, str) and "\\" in v:
            return v.replace("\\", "/")
        return v

    out = _fix_paths(out)

    # 3) Normalize findings: remove fingerprints/ast hashes + re-stable IDs
    findings = out.get("findings_raw", []) or []
    # Sort deterministically by location + message so ID reassignment is stable
    findings.sort(
        key=lambda f: (
            f.get("type", ""),
            (f.get("location", {}) or {}).get("path", ""),
            (f.get("location", {}) or {}).get("line_start", 0),
            f.get("message", ""),
        )
    )

    id_map: dict[str, str] = {}
    for i, f in enumerate(findings):
        old_id = f.get("finding_id", "")
        new_id = f"F{i:04d}"
        if old_id:
            id_map[old_id] = new_id
        f["finding_id"] = new_id
        f.pop("fingerprint", None)
        meta = f.get("metadata")
        if isinstance(meta, dict):
            meta.pop("ast_hash", None)

    out["findings_raw"] = findings

    # 4) Normalize signals: stable IDs + rewrite evidence.finding_ids
    signals = out.get("signals_snapshot", []) or []
    signals.sort(
        key=lambda s: (
            s.get("type", ""),
            s.get("summary_key", ""),
            (s.get("evidence", {}) or {}).get("primary_location", {}).get("path", ""),
        )
    )
    for i, s in enumerate(signals):
        s["signal_id"] = f"S{i:04d}"
        ev = s.get("evidence")
        if isinstance(ev, dict):
            fids = ev.get("finding_ids")
            if isinstance(fids, list):
                ev["finding_ids"] = [id_map.get(x, x) for x in fids]
                ev["finding_ids"].sort()

    out["signals_snapshot"] = signals

    return out


@pytest.mark.integration
class TestGoldenFixtures:
    """Golden tests: fixtures are the semantic contract for signal_logic_version.

    If this test fails due to intended behavior change, bump signal_logic_version
    and update the golden JSON outputs in tests/fixtures/expected/.
    """

    @pytest.fixture(
        params=sorted(
            p.name for p in FIXTURES_DIR.iterdir() if p.is_dir()
        ) if FIXTURES_DIR.exists() else [],
    )
    def fixture_name(self, request: pytest.FixtureRequest) -> str:
        return request.param

    def test_golden_output_matches(
        self, fixture_name: str, tmp_path: Path
    ) -> None:
        fixture_path = FIXTURES_DIR / fixture_name
        expected_path = EXPECTED_DIR / f"{fixture_name}_run_result.json"

        result = _golden_run(fixture_path, tmp_path)

        # Always validate against schema
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.validate(result, schema)

        if not expected_path.exists():
            # Auto-generate expected output on first run
            EXPECTED_DIR.mkdir(parents=True, exist_ok=True)
            expected_path.write_text(
                json.dumps(
                    _normalize(result), indent=2, sort_keys=True, default=str
                )
                + "\n",
                encoding="utf-8",
            )
            pytest.skip(
                f"Generated golden output: {expected_path.name} — "
                f"re-run to compare."
            )

        expected = _normalize(json.loads(expected_path.read_text(encoding="utf-8")))
        actual = _normalize(result)

        assert actual == expected, (
            f"Golden output mismatch for {fixture_name}.\n"
            f"If this is intentional, bump signal_logic_version and "
            f"delete {expected_path} to regenerate."
        )

    def test_schema_valid(self, fixture_name: str, tmp_path: Path) -> None:
        """Every golden fixture output must validate against the schema."""
        fixture_path = FIXTURES_DIR / fixture_name
        result = _golden_run(fixture_path, tmp_path)
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.validate(result, schema)
