"""
Silent Fallback Analyzer Tests
==============================
Unit and integration tests for the SilentFallbackAnalyzer.

Covers:
  - SF_INCOMPLETE_DISPATCH_001: incomplete dispatch on Literal/Enum parameters
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from code_audit.analyzers.silent_fallback import SilentFallbackAnalyzer
from code_audit.model import AnalyzerType, Severity
from code_audit.rules import SF_INCOMPLETE_DISPATCH_001


@pytest.fixture
def analyzer() -> SilentFallbackAnalyzer:
    return SilentFallbackAnalyzer()


@pytest.fixture
def fixtures_root() -> Path:
    return Path(__file__).parent / "fixtures" / "silent_fallback"


def _write(tmp_path: Path, code: str, name: str = "target.py") -> Path:
    """Write *code* to a temp .py file and return the file path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


# ============================================================================
# Positive fixture tests — rule should fire
# ============================================================================


class TestPositiveFixtures:
    """Tests that verify the rule fires on positive fixtures."""

    def test_literal_partial_dispatch(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Detect incomplete dispatch on Literal type."""
        path = fixtures_root / "positive" / "literal_partial_dispatch.py"
        findings = analyzer.run(fixtures_root, [path])

        assert len(findings) == 1
        f = findings[0]
        assert f.type == AnalyzerType.SILENT_FALLBACK
        assert f.severity == Severity.MEDIUM
        assert f.metadata["rule_id"] == SF_INCOMPLETE_DISPATCH_001
        assert "pythagorean" in f.metadata["missing_values"]
        assert "compute_temperament" in f.message

    def test_enum_partial_dispatch(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Detect incomplete dispatch on Enum type with silent default."""
        path = fixtures_root / "positive" / "enum_partial_dispatch.py"
        findings = analyzer.run(fixtures_root, [path])

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["rule_id"] == SF_INCOMPLETE_DISPATCH_001
        assert "CAM_READY_R2000" in f.metadata["missing_values"]
        assert "process" in f.message

    def test_match_statement_partial(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Detect incomplete match statement."""
        path = fixtures_root / "positive" / "match_statement_partial.py"
        findings = analyzer.run(fixtures_root, [path])

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["rule_id"] == SF_INCOMPLETE_DISPATCH_001
        assert "toml" in f.metadata["missing_values"]

    def test_elif_chain_no_else(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Detect StrEnum dispatch without else clause."""
        path = fixtures_root / "positive" / "elif_chain_no_else.py"
        findings = analyzer.run(fixtures_root, [path])

        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["rule_id"] == SF_INCOMPLETE_DISPATCH_001
        assert "XML" in f.metadata["missing_values"]


# ============================================================================
# Negative fixture tests — rule should NOT fire
# ============================================================================


class TestNegativeFixtures:
    """Tests that verify the rule does NOT fire on negative fixtures."""

    def test_literal_complete_dispatch(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """All Literal values handled with else raise."""
        path = fixtures_root / "negative" / "literal_complete_dispatch.py"
        findings = analyzer.run(fixtures_root, [path])
        assert len(findings) == 0

    def test_enum_complete_dispatch(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """All Enum members handled explicitly."""
        path = fixtures_root / "negative" / "enum_complete_dispatch.py"
        findings = analyzer.run(fixtures_root, [path])
        assert len(findings) == 0

    def test_partial_with_raise(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Partial dispatch but function ends with raise."""
        path = fixtures_root / "negative" / "partial_with_raise.py"
        findings = analyzer.run(fixtures_root, [path])
        assert len(findings) == 0

    def test_generic_str_param(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Generic str type — cannot enumerate value space."""
        path = fixtures_root / "negative" / "generic_str_param.py"
        findings = analyzer.run(fixtures_root, [path])
        assert len(findings) == 0

    def test_single_value_no_dispatch(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Typed parameter exists but no dispatch logic."""
        path = fixtures_root / "negative" / "single_value_no_dispatch.py"
        findings = analyzer.run(fixtures_root, [path])
        assert len(findings) == 0

    def test_nested_function_unrelated(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Nested function has different parameter."""
        path = fixtures_root / "negative" / "nested_function_unrelated.py"
        findings = analyzer.run(fixtures_root, [path])
        assert len(findings) == 0

    def test_match_with_wildcard_raise(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Match statement with wildcard case that raises."""
        path = fixtures_root / "negative" / "match_with_wildcard_raise.py"
        findings = analyzer.run(fixtures_root, [path])
        assert len(findings) == 0


# ============================================================================
# Edge cases and error handling
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_syntax_error_file_skipped(
        self, analyzer: SilentFallbackAnalyzer, tmp_path: Path
    ) -> None:
        """Files with syntax errors are skipped gracefully."""
        path = _write(tmp_path, "def broken(\n", "bad.py")
        findings = analyzer.run(tmp_path, [path])
        assert len(findings) == 0

    def test_no_typed_params_no_findings(
        self, analyzer: SilentFallbackAnalyzer, tmp_path: Path
    ) -> None:
        """File without Literal/Enum parameters produces no findings."""
        path = _write(
            tmp_path,
            """
            def simple_func(x, y):
                if x == 1:
                    return "one"
                return "other"
            """,
        )
        findings = analyzer.run(tmp_path, [path])
        assert len(findings) == 0

    def test_empty_file_no_findings(
        self, analyzer: SilentFallbackAnalyzer, tmp_path: Path
    ) -> None:
        """Empty file produces no findings."""
        path = _write(tmp_path, "", "empty.py")
        findings = analyzer.run(tmp_path, [path])
        assert len(findings) == 0

    def test_private_enum_members_skipped(
        self, analyzer: SilentFallbackAnalyzer, tmp_path: Path
    ) -> None:
        """Private enum members (starting with _) are not counted."""
        path = _write(
            tmp_path,
            """
            from enum import Enum

            class Mode(Enum):
                _internal = "internal"
                PUBLIC = "public"

            def process(mode: Mode) -> str:
                if mode == Mode.PUBLIC:
                    return "public_output"
                # _internal is private, should not be required
            """,
        )
        findings = analyzer.run(tmp_path, [path])
        assert len(findings) == 0

    def test_multiple_typed_params(
        self, analyzer: SilentFallbackAnalyzer, tmp_path: Path
    ) -> None:
        """Function with multiple typed params checked independently."""
        path = _write(
            tmp_path,
            """
            from typing import Literal

            def process(fmt: Literal["a", "b"], mode: Literal["x", "y"]) -> str:
                if fmt == "a":
                    pass
                # Missing "b" for fmt
                if mode == "x":
                    pass
                elif mode == "y":
                    pass
                # mode is complete
            """,
        )
        findings = analyzer.run(tmp_path, [path])
        # Should only fire for fmt (missing "b"), not for mode
        assert len(findings) == 1
        assert findings[0].metadata["param"] == "fmt"
        assert "b" in findings[0].metadata["missing_values"]


# ============================================================================
# Finding structure tests
# ============================================================================


class TestFindingStructure:
    """Tests for finding metadata and structure."""

    def test_finding_has_required_fields(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Finding includes all required metadata."""
        path = fixtures_root / "positive" / "literal_partial_dispatch.py"
        findings = analyzer.run(fixtures_root, [path])

        assert len(findings) == 1
        f = findings[0]

        # Required fields
        assert f.finding_id.startswith("sf_")
        assert f.type == AnalyzerType.SILENT_FALLBACK
        assert f.severity == Severity.MEDIUM
        assert 0 < f.confidence <= 1.0
        assert f.message
        assert f.location.path
        assert f.location.line_start > 0
        assert f.fingerprint.startswith("sha256:")
        assert f.snippet

        # Metadata
        assert "rule_id" in f.metadata
        assert "param" in f.metadata
        assert "missing_values" in f.metadata
        assert "handled_values" in f.metadata

    def test_fingerprint_is_deterministic(
        self, analyzer: SilentFallbackAnalyzer, fixtures_root: Path
    ) -> None:
        """Same input produces same fingerprint."""
        path = fixtures_root / "positive" / "literal_partial_dispatch.py"

        findings1 = analyzer.run(fixtures_root, [path])
        findings2 = analyzer.run(fixtures_root, [path])

        assert len(findings1) == len(findings2) == 1
        assert findings1[0].fingerprint == findings2[0].fingerprint
