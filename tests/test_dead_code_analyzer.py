"""
Dead Code Analyzer Tests
========================
Unit and integration tests for the DeadCodeAnalyzer.

Covers:
  - DC_UNREACHABLE_001: statements after return/raise/break/continue
  - DC_IF_FALSE_001: if False: / while False: blocks
  - DC_ASSERT_FALSE_001: assert False patterns
"""

import pytest
from pathlib import Path
import tempfile
import textwrap

from code_audit.analyzers.dead_code import DeadCodeAnalyzer
from code_audit.model import AnalyzerType, Severity


@pytest.fixture
def analyzer():
    return DeadCodeAnalyzer()


@pytest.fixture
def temp_repo():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def write_py(root: Path, name: str, content: str) -> Path:
    """Write a Python file with dedented content."""
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ============================================================================
# DC_UNREACHABLE_001 — statements after terminators
# ============================================================================

class TestUnreachableDetected:
    """Tests for DC_UNREACHABLE_001 rule."""

    def test_unreachable_after_return(self, analyzer, temp_repo):
        """Detect code after return statement."""
        write_py(temp_repo, "app.py", """
            def foo():
                return 1
                print("never")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "DC_UNREACHABLE_001"
        assert findings[0].metadata["terminator"] == "return"
        assert findings[0].severity == Severity.HIGH

    def test_unreachable_after_raise(self, analyzer, temp_repo):
        """Detect code after raise statement."""
        write_py(temp_repo, "app.py", """
            def foo():
                raise ValueError("oops")
                print("never")
                x = 1
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["terminator"] == "raise"
        assert findings[0].metadata["unreachable_count"] == 2

    def test_unreachable_after_break(self, analyzer, temp_repo):
        """Detect code after break statement."""
        write_py(temp_repo, "app.py", """
            def foo():
                for i in range(10):
                    break
                    print("never")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["terminator"] == "break"

    def test_unreachable_after_continue(self, analyzer, temp_repo):
        """Detect code after continue statement."""
        write_py(temp_repo, "app.py", """
            def foo():
                for i in range(10):
                    continue
                    print("never")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["terminator"] == "continue"

    def test_unreachable_in_else_branch(self, analyzer, temp_repo):
        """Detect code after terminator in else branch."""
        write_py(temp_repo, "app.py", """
            def foo(x):
                if x:
                    pass
                else:
                    return 0
                    print("dead")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["terminator"] == "return"

    def test_multiple_unreachable_blocks(self, analyzer, temp_repo):
        """Detect multiple unreachable blocks in same file."""
        write_py(temp_repo, "app.py", """
            def foo():
                return 1
                print("dead1")

            def bar():
                raise Exception()
                print("dead2")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 2


# ============================================================================
# DC_IF_FALSE_001 — if False: / while False: blocks
# ============================================================================

class TestIfFalseDetected:
    """Tests for DC_IF_FALSE_001 rule."""

    def test_if_false_block(self, analyzer, temp_repo):
        """Detect if False: block."""
        write_py(temp_repo, "app.py", """
            if False:
                print("never")
                x = 1
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "DC_IF_FALSE_001"
        assert findings[0].metadata["block_type"] == "if"
        assert findings[0].metadata["dead_statement_count"] == 2
        assert findings[0].severity == Severity.HIGH

    def test_while_false_block(self, analyzer, temp_repo):
        """Detect while False: block."""
        write_py(temp_repo, "app.py", """
            while False:
                print("never")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "DC_IF_FALSE_001"
        assert findings[0].metadata["block_type"] == "while"

    def test_if_false_in_function(self, analyzer, temp_repo):
        """Detect if False: inside function."""
        write_py(temp_repo, "app.py", """
            def foo():
                if False:
                    return "never"
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["context"] == "foo"


# ============================================================================
# DC_ASSERT_FALSE_001 — assert False patterns
# ============================================================================

class TestAssertFalseDetected:
    """Tests for DC_ASSERT_FALSE_001 rule."""

    def test_assert_false(self, analyzer, temp_repo):
        """Detect assert False statement."""
        write_py(temp_repo, "app.py", """
            def foo():
                assert False
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "DC_ASSERT_FALSE_001"
        assert findings[0].severity == Severity.MEDIUM

    def test_assert_zero(self, analyzer, temp_repo):
        """Detect assert 0 statement (equivalent to assert False)."""
        write_py(temp_repo, "app.py", """
            def foo():
                assert 0
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "DC_ASSERT_FALSE_001"


# ============================================================================
# Negative cases — no false positives
# ============================================================================

class TestNoFalsePositives:
    """Tests for patterns that should NOT be flagged."""

    def test_conditional_return(self, analyzer, temp_repo):
        """Code after conditional return is reachable."""
        write_py(temp_repo, "app.py", """
            def foo(x):
                if x:
                    return 1
                print("reachable")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0

    def test_if_true_not_flagged(self, analyzer, temp_repo):
        """if True: is not dead code."""
        write_py(temp_repo, "app.py", """
            if True:
                print("always")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0

    def test_normal_while_loop(self, analyzer, temp_repo):
        """Normal while loop is not dead code."""
        write_py(temp_repo, "app.py", """
            x = True
            while x:
                print("maybe")
                x = False
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0

    def test_assert_true_not_flagged(self, analyzer, temp_repo):
        """assert True is not dead code."""
        write_py(temp_repo, "app.py", """
            def foo():
                assert True
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0

    def test_normal_assert(self, analyzer, temp_repo):
        """Normal assert is not dead code."""
        write_py(temp_repo, "app.py", """
            def foo(x):
                assert x > 0
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0

    def test_return_at_end_of_function(self, analyzer, temp_repo):
        """Return at end of function is fine."""
        write_py(temp_repo, "app.py", """
            def foo():
                x = 1
                return x
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0

    def test_clean_file(self, analyzer, temp_repo):
        """Clean file has no findings."""
        write_py(temp_repo, "app.py", """
            def add(a, b):
                return a + b

            def greet(name):
                print(f"Hello, {name}")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0


# ============================================================================
# Integration with fixtures
# ============================================================================

class TestFixtureRepos:
    """Tests using fixture repos."""

    def test_dead_code_hot_fixture(self, analyzer):
        """Fixture with all dead code patterns is detected."""
        fixture_path = Path(__file__).parent / "fixtures" / "repos" / "dead_code_hot"
        if not fixture_path.exists():
            pytest.skip("Fixture not created yet")

        src_path = fixture_path / "src" / "app.py"
        findings = analyzer.run(fixture_path, [src_path])

        # Should detect all 3 rule types
        rule_ids = {f.metadata["rule_id"] for f in findings}
        assert "DC_UNREACHABLE_001" in rule_ids
        assert "DC_IF_FALSE_001" in rule_ids
        assert "DC_ASSERT_FALSE_001" in rule_ids

    def test_dead_code_clean_fixture(self, analyzer):
        """Clean fixture has no findings."""
        fixture_path = Path(__file__).parent / "fixtures" / "repos" / "dead_code_clean"
        if not fixture_path.exists():
            pytest.skip("Fixture not created yet")

        src_path = fixture_path / "src" / "app.py"
        findings = analyzer.run(fixture_path, [src_path])

        assert len(findings) == 0


# ============================================================================
# Signal integration
# ============================================================================

class TestDeadCodeSignal:
    """Tests for dead code signal translation."""

    def test_signal_aggregation(self, analyzer, temp_repo):
        """Dead code findings aggregate into one signal."""
        from code_audit.insights.translator import findings_to_signals

        write_py(temp_repo, "app.py", """
            def foo():
                return 1
                print("dead")

            if False:
                x = 1

            def bar():
                assert False
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])
        signals = findings_to_signals(findings)

        assert len(signals) == 1
        assert signals[0]["type"] == "dead_code"
        assert "unreachable_count" in signals[0]["evidence"]["summary"]
        assert "if_false_count" in signals[0]["evidence"]["summary"]

    def test_no_signal_when_clean(self, analyzer, temp_repo):
        """Clean file produces no dead code signal."""
        from code_audit.insights.translator import findings_to_signals

        write_py(temp_repo, "app.py", """
            def add(a, b):
                return a + b
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])
        signals = findings_to_signals(findings)

        assert len(signals) == 0


# ============================================================================
# API integration
# ============================================================================

class TestAPIIntegration:
    """Tests for API integration."""

    def test_scan_project_includes_dead_code(self, temp_repo):
        """scan_project includes dead code findings."""
        from code_audit.api import scan_project

        write_py(temp_repo, "app.py", """
            def foo():
                return 1
                print("dead")
        """)

        _, result = scan_project(temp_repo, ci_mode=True)

        # Check findings include dead_code type
        findings = result.get("findings_raw", [])
        dead_code_findings = [f for f in findings if f.get("type") == "dead_code"]
        assert len(dead_code_findings) >= 1

    def test_clean_repo_has_no_dead_code(self, temp_repo):
        """Clean repo has no dead code findings."""
        from code_audit.api import scan_project

        write_py(temp_repo, "app.py", """
            def add(a, b):
                return a + b
        """)

        _, result = scan_project(temp_repo, ci_mode=True)

        findings = result.get("findings_raw", [])
        dead_code_findings = [f for f in findings if f.get("type") == "dead_code"]
        assert len(dead_code_findings) == 0


# ============================================================================
# Determinism
# ============================================================================

class TestDeterminism:
    """Tests for deterministic output."""

    def test_stable_finding_ids(self, analyzer, temp_repo):
        """Finding IDs are stable across runs."""
        write_py(temp_repo, "app.py", """
            def foo():
                return 1
                print("dead")
        """)

        findings1 = analyzer.run(temp_repo, [temp_repo / "app.py"])
        findings2 = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert findings1[0].finding_id == findings2[0].finding_id
        assert findings1[0].fingerprint == findings2[0].fingerprint

    def test_posix_paths(self, analyzer, temp_repo):
        """Paths are POSIX-style (forward slashes)."""
        write_py(temp_repo, "app.py", """
            def foo():
                return 1
                print("dead")
        """)

        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert "\\" not in findings[0].location.path
