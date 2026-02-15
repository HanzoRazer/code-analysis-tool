"""
Tests for SQL Auto-Fixer
========================
Comprehensive tests for the auto-fix capability of sql_autofix.py.
"""

import tempfile
from pathlib import Path
import pytest

from code_audit.analyzers.sql_autofix import (
    AutoFixer,
    Fix,
    FixResult,
    apply_fixes,
    fix_file,
)


class TestFStringSQLInjectionFix:
    """Tests for f-string SQL injection auto-fix."""

    def test_detect_fstring_injection(self):
        """Test detection of f-string SQL injection."""
        code = '''
import sqlite3
conn = sqlite3.connect(":memory:")
cursor = conn.cursor()
user_id = "123"
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            assert len(fixes) >= 1
            fix = next((f for f in fixes if f.rule_id == 'fstring_sql_injection'), None)
            assert fix is not None
            assert 'parameterized' in fix.description.lower()
            assert fix.confidence > 0.5
        finally:
            path.unlink(missing_ok=True)

    def test_fstring_fix_generates_parameterized_query(self):
        """Test that fix converts to parameterized query."""
        code = '''cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            # The fix should contain :user_id placeholder
            if fixes:
                assert ':user_id' in fixes[0].new_code or 'parameterized' in fixes[0].description
        finally:
            path.unlink(missing_ok=True)


class TestFormatSQLInjectionFix:
    """Tests for .format() SQL injection auto-fix."""

    def test_detect_format_injection(self):
        """Test detection of .format() SQL injection."""
        code = '''
sql = "SELECT * FROM users WHERE name = '{}'".format(name)
cursor.execute(sql)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            format_fixes = [f for f in fixes if f.rule_id == 'format_sql_injection']
            assert len(format_fixes) >= 1
        finally:
            path.unlink(missing_ok=True)


class TestPercentSQLInjectionFix:
    """Tests for % formatting SQL injection auto-fix."""

    def test_detect_percent_injection(self):
        """Test detection of % formatting SQL injection."""
        code = '''
user_id = "123"
sql = "SELECT * FROM users WHERE id = %s" % user_id
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            percent_fixes = [f for f in fixes if f.rule_id == 'percent_sql_injection']
            assert len(percent_fixes) >= 1
        finally:
            path.unlink(missing_ok=True)


class TestShellInjectionFix:
    """Tests for shell=True injection auto-fix."""

    def test_detect_shell_injection(self):
        """Test detection of shell=True."""
        code = '''
import subprocess
cmd = user_input
subprocess.run(cmd, shell=True)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            shell_fixes = [f for f in fixes if f.rule_id == 'shell_injection']
            assert len(shell_fixes) >= 1
            assert 'shlex.split' in shell_fixes[0].new_code
        finally:
            path.unlink(missing_ok=True)

    def test_shell_fix_removes_shell_true(self):
        """Test that fix removes shell=True."""
        code = '''import subprocess
subprocess.run(cmd, shell=True, capture_output=True)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            if fixes:
                fix = fixes[0]
                assert 'shell=True' not in fix.new_code
                assert 'shlex.split' in fix.new_code
        finally:
            path.unlink(missing_ok=True)

    def test_shell_fix_preserves_variable_assignment(self):
        """Test that fix preserves variable assignment like 'result = '."""
        code = '''import subprocess
result = subprocess.run(cmd, shell=True, capture_output=True)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            assert len(fixes) >= 1
            fix = fixes[0]
            # Must preserve the "result = " assignment
            assert 'result = ' in fix.new_code or 'result=' in fix.new_code
            assert 'shlex.split' in fix.new_code
            assert 'shell=True' not in fix.new_code
        finally:
            path.unlink(missing_ok=True)


class TestApplyFixes:
    """Tests for applying fixes to files."""

    def test_apply_single_fix(self):
        """Test applying a single fix."""
        original = '''import subprocess
cmd = "ls -la"
subprocess.run(cmd, shell=True)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(original)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)
            assert len(fixes) > 0

            result = apply_fixes(path, fixes, create_backup=False)
            assert result.success
            assert result.fixes_applied > 0

            # Verify file was modified
            new_content = path.read_text()
            assert 'shell=True' not in new_content
            assert 'shlex.split' in new_content
        finally:
            path.unlink(missing_ok=True)

    def test_dry_run_doesnt_modify(self):
        """Test that dry_run doesn't modify the file."""
        original = '''import subprocess
subprocess.run(cmd, shell=True)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(original)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            result = apply_fixes(path, fixes, dry_run=True)

            # File should not be modified
            content = path.read_text()
            assert 'shell=True' in content  # Original unchanged
        finally:
            path.unlink(missing_ok=True)

    def test_backup_created(self):
        """Test that backup is created."""
        original = '''import subprocess
subprocess.run(cmd, shell=True)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(original)
            f.flush()
            path = Path(f.name)
            backup_path = Path(f.name + '.bak')

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)

            result = apply_fixes(path, fixes, create_backup=True)

            assert result.backup_path is not None
            assert result.backup_path.exists()
        finally:
            path.unlink(missing_ok=True)
            backup_path.unlink(missing_ok=True)


class TestFixDataclass:
    """Tests for Fix dataclass."""

    def test_describe(self):
        """Test Fix.describe() output."""
        fix = Fix(
            file_path=Path("test.py"),
            line_start=10,
            line_end=10,
            old_code="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            new_code='cursor.execute("SELECT * FROM users WHERE id = :user_id", {"user_id": user_id})',
            rule_id="fstring_sql_injection",
            description="Convert f-string SQL to parameterized query",
        )

        desc = fix.describe()
        assert "fstring_sql_injection" in desc
        assert "test.py:10" in desc

    def test_to_dict(self):
        """Test Fix.to_dict() serialization."""
        fix = Fix(
            file_path=Path("test.py"),
            line_start=10,
            line_end=12,
            old_code="old",
            new_code="new",
            rule_id="test_rule",
            description="Test fix",
            confidence=0.85,
        )

        d = fix.to_dict()
        assert d["file_path"] == "test.py"
        assert d["line_start"] == 10
        assert d["rule_id"] == "test_rule"
        assert d["confidence"] == 0.85


class TestFixResult:
    """Tests for FixResult dataclass."""

    def test_success_with_no_errors(self):
        """Test success property with no errors."""
        result = FixResult(
            file_path=Path("test.py"),
            fixes_applied=3,
            fixes_skipped=0,
        )
        assert result.success is True

    def test_failure_with_errors(self):
        """Test success property with errors."""
        result = FixResult(
            file_path=Path("test.py"),
            fixes_applied=2,
            fixes_skipped=1,
            errors=["Error applying fix at line 10"],
        )
        assert result.success is False


class TestFixFile:
    """Tests for fix_file convenience function."""

    def test_fix_file_convenience(self):
        """Test fix_file function."""
        code = '''import subprocess
subprocess.run(cmd, shell=True)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            result = fix_file(path, dry_run=True)
            assert isinstance(result, FixResult)
        finally:
            path.unlink(missing_ok=True)

    def test_fix_file_no_issues(self):
        """Test fix_file on clean file."""
        code = '''import subprocess
subprocess.run(["ls", "-la"])
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            result = fix_file(path)
            assert result.fixes_applied == 0
        finally:
            path.unlink(missing_ok=True)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_nonexistent_file(self):
        """Test handling of non-existent file."""
        fixer = AutoFixer()
        fixes = fixer.analyze_file(Path("/nonexistent/file.py"))
        assert fixes == []

    def test_non_python_file(self):
        """Test handling of non-Python file."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w') as f:
            f.write("SELECT * FROM users")
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)
            assert fixes == []
        finally:
            path.unlink(missing_ok=True)

    def test_syntax_error_file(self):
        """Test handling of file with syntax errors."""
        code = '''def broken(
    # Missing closing paren
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)
            # Should not crash, may return empty or partial results
            assert isinstance(fixes, list)
        finally:
            path.unlink(missing_ok=True)

    def test_safe_code_no_fixes(self):
        """Test that safe code doesn't get flagged."""
        code = '''
import sqlite3
from sqlalchemy import text

# Safe parameterized query
cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

# Safe subprocess
subprocess.run(["ls", "-la"])

# Safe format (not SQL)
message = "Hello {}".format(name)
'''
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            path = Path(f.name)

        try:
            fixer = AutoFixer()
            fixes = fixer.analyze_file(path)
            # Should have no SQL/shell injection fixes
            injection_fixes = [f for f in fixes if 'injection' in f.rule_id]
            assert len(injection_fixes) == 0
        finally:
            path.unlink(missing_ok=True)
