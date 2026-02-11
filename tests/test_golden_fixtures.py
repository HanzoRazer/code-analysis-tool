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
    """Strip run.config.root (machine-dependent) for stable comparison."""
    out = json.loads(json.dumps(d, sort_keys=True, default=str))
    if "run" in out and "config" in out["run"]:
        out["run"]["config"].pop("root", None)
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

        expected = json.loads(expected_path.read_text(encoding="utf-8"))
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
