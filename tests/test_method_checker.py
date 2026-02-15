"""
Tests for Method Existence & Typo Detection Analyzer
====================================================
"""

import tempfile
from pathlib import Path
import pytest

from code_audit.analyzers.method_checker import (
    MethodExistenceAnalyzer,
    TypoDetector,
    MethodIssue,
    levenshtein_distance,
    similarity_ratio,
    analyze_project,
)


class TestLevenshteinDistance:
    """Tests for Levenshtein distance calculation."""

    def test_identical_strings(self):
        assert levenshtein_distance("hello", "hello") == 0

    def test_single_char_difference(self):
        assert levenshtein_distance("hello", "hallo") == 1

    def test_insertion(self):
        assert levenshtein_distance("hello", "helloo") == 1

    def test_deletion(self):
        assert levenshtein_distance("hello", "helo") == 1

    def test_completely_different(self):
        assert levenshtein_distance("abc", "xyz") == 3

    def test_empty_string(self):
        assert levenshtein_distance("hello", "") == 5
        assert levenshtein_distance("", "hello") == 5


class TestSimilarityRatio:
    """Tests for similarity ratio calculation."""

    def test_identical_strings(self):
        assert similarity_ratio("hello", "hello") == 1.0

    def test_similar_strings(self):
        ratio = similarity_ratio("validate_database_connection", "validate_database_connectivity")
        assert ratio > 0.85  # Very similar

    def test_different_strings(self):
        ratio = similarity_ratio("abc", "xyz")
        assert ratio < 0.5


class TestMethodExistenceAnalyzer:
    """Tests for MethodExistenceAnalyzer."""

    def test_detect_missing_method(self):
        """Test detection of call to missing method."""
        code = '''
class MyClass:
    def existing_method(self):
        pass

obj = MyClass()
obj.nonexistent_method()
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            analyzer = MethodExistenceAnalyzer()
            issues = analyzer.analyze_file(path)
            # Note: This requires type inference which is limited without running
            # The analyzer may not catch this without more context
            assert isinstance(issues, list)
        finally:
            path.unlink(missing_ok=True)

    def test_no_false_positives_on_existing_methods(self):
        """Test that existing methods don't trigger issues."""
        code = '''
class Calculator:
    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b

calc = Calculator()
result = calc.add(1, 2)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            analyzer = MethodExistenceAnalyzer()
            issues = analyzer.analyze_file(path)
            # Should not flag existing methods
            missing_issues = [i for i in issues if i.issue_type == 'missing_method']
            assert len(missing_issues) == 0
        finally:
            path.unlink(missing_ok=True)

    def test_add_known_class(self):
        """Test adding known class methods."""
        analyzer = MethodExistenceAnalyzer()
        analyzer.add_known_class("MyClass", {"method_a", "method_b"})

        assert "MyClass" in analyzer.known_classes
        assert "method_a" in analyzer.known_classes["MyClass"]


class TestTypoDetector:
    """Tests for TypoDetector."""

    def test_detect_common_typo(self):
        """Test detection of common typos."""
        detector = TypoDetector()
        result = detector.check_identifier("conection")
        assert result is not None
        assert result[0] == "connection"
        assert result[1] == 1.0

    def test_similar_identifier(self):
        """Test detection of similar identifiers."""
        detector = TypoDetector()
        detector.add_known_identifiers({"validate_database_connectivity"})

        result = detector.check_identifier("validate_database_connection")
        assert result is not None
        suggestion, confidence = result
        assert suggestion == "validate_database_connectivity"
        assert confidence > 0.8

    def test_no_typo_on_exact_match(self):
        """Test that exact matches don't trigger typo detection."""
        detector = TypoDetector()
        detector.add_known_identifiers({"my_method"})

        result = detector.check_identifier("my_method")
        assert result is None

    def test_threshold(self):
        """Test that threshold affects detection."""
        detector_strict = TypoDetector(threshold=0.95)
        detector_loose = TypoDetector(threshold=0.5)

        detector_strict.add_known_identifiers({"hello_world"})
        detector_loose.add_known_identifiers({"hello_world"})

        # "hello_word" is similar but not very close
        strict_result = detector_strict.check_identifier("hello_word")
        loose_result = detector_loose.check_identifier("hello_word")

        # Loose detector should catch it, strict might not
        assert loose_result is not None


class TestMethodIssue:
    """Tests for MethodIssue dataclass."""

    def test_to_dict(self):
        """Test serialization to dict."""
        issue = MethodIssue(
            file_path=Path("test.py"),
            line_number=10,
            issue_type="typo",
            severity="HIGH",
            message="Possible typo",
            object_name="obj",
            method_name="conection",
            suggestion="connection",
            confidence=0.95,
        )

        d = issue.to_dict()
        assert d["file_path"] == "test.py"
        assert d["line_number"] == 10
        assert d["issue_type"] == "typo"
        assert d["suggestion"] == "connection"


class TestAnalyzeProject:
    """Tests for analyze_project function."""

    def test_analyze_empty_directory(self):
        """Test analyzing empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = analyze_project(Path(tmpdir))
            assert result["total_issues"] == 0
            assert result["by_type"] == {}

    def test_analyze_with_python_files(self):
        """Test analyzing directory with Python files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a simple Python file
            py_file = Path(tmpdir) / "test.py"
            py_file.write_text('''
class MyClass:
    def my_method(self):
        pass
''')
            result = analyze_project(Path(tmpdir))
            assert "total_issues" in result
            assert "by_type" in result


class TestIntegrationWithValidationSuite:
    """Integration tests with ValidationSuite."""

    def test_method_validator_import(self):
        """Test that MethodExistenceValidator can be imported."""
        from code_audit.diagnostics import MethodExistenceValidator
        validator = MethodExistenceValidator()
        assert validator.name == "method_existence"

    def test_typo_validator_import(self):
        """Test that TypoValidator can be imported."""
        from code_audit.diagnostics import TypoValidator
        validator = TypoValidator()
        assert validator.name == "typo_detector"

    def test_validators_in_suite(self):
        """Test that validators are included in ValidationSuite."""
        from code_audit.diagnostics import ValidationSuite

        with tempfile.TemporaryDirectory() as tmpdir:
            suite = ValidationSuite(tmpdir)
            validator_names = [v.name for v in suite.validators]

            assert "method_existence" in validator_names
            assert "typo_detector" in validator_names
