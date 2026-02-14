"""
Security Analyzer Tests
=======================
Unit and integration tests for the SecurityAnalyzer.

Covers:
  - SEC_HARDCODED_SECRET_001: hardcoded passwords/keys/tokens
  - SEC_EVAL_001: eval()/exec() usage
  - SEC_SUBPROCESS_SHELL_001: subprocess with shell=True
  - SEC_SQL_INJECTION_001: SQL string formatting
  - SEC_PICKLE_LOAD_001: pickle.load/loads
  - SEC_YAML_UNSAFE_001: yaml.load without SafeLoader
"""

import pytest
from pathlib import Path
import tempfile
import textwrap

from code_audit.analyzers.security import SecurityAnalyzer
from code_audit.model import AnalyzerType, Severity


@pytest.fixture
def analyzer():
    return SecurityAnalyzer()


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
# SEC_HARDCODED_SECRET_001 — hardcoded secrets
# ============================================================================

class TestHardcodedSecretDetected:
    """Tests for SEC_HARDCODED_SECRET_001 rule."""

    def test_hardcoded_password(self, analyzer, temp_repo):
        """Detect hardcoded password assignment."""
        write_py(temp_repo, "app.py", """
            password = "secret123"
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "SEC_HARDCODED_SECRET_001"
        assert findings[0].metadata["variable_name"] == "password"
        assert findings[0].severity == Severity.CRITICAL

    def test_hardcoded_api_key(self, analyzer, temp_repo):
        """Detect hardcoded API key."""
        write_py(temp_repo, "app.py", """
            api_key = "sk-1234567890abcdef"
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["variable_name"] == "api_key"

    def test_hardcoded_secret_token(self, analyzer, temp_repo):
        """Detect hardcoded secret token."""
        write_py(temp_repo, "app.py", """
            secret_token = "abc123xyz789"
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["variable_name"] == "secret_token"

    def test_hardcoded_db_password(self, analyzer, temp_repo):
        """Detect hardcoded database password."""
        write_py(temp_repo, "app.py", """
            db_password = "postgres123"
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1

    def test_multiple_secrets(self, analyzer, temp_repo):
        """Detect multiple hardcoded secrets."""
        write_py(temp_repo, "app.py", """
            password = "secret1"
            api_key = "key123"
            auth_token = "token456"
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 3


# ============================================================================
# SEC_EVAL_001 — eval/exec usage
# ============================================================================

class TestEvalExecDetected:
    """Tests for SEC_EVAL_001 rule."""

    def test_eval_call(self, analyzer, temp_repo):
        """Detect eval() usage."""
        write_py(temp_repo, "app.py", """
            result = eval(user_input)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "SEC_EVAL_001"
        assert findings[0].metadata["function"] == "eval"
        assert findings[0].severity == Severity.CRITICAL

    def test_exec_call(self, analyzer, temp_repo):
        """Detect exec() usage."""
        write_py(temp_repo, "app.py", """
            exec(code_string)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["function"] == "exec"

    def test_eval_in_function(self, analyzer, temp_repo):
        """Detect eval() inside function."""
        write_py(temp_repo, "app.py", """
            def calculate(expr):
                return eval(expr)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["context"] == "calculate"


# ============================================================================
# SEC_SUBPROCESS_SHELL_001 — subprocess shell injection
# ============================================================================

class TestSubprocessShellDetected:
    """Tests for SEC_SUBPROCESS_SHELL_001 rule."""

    def test_subprocess_shell_true(self, analyzer, temp_repo):
        """Detect subprocess.run with shell=True."""
        write_py(temp_repo, "app.py", """
            import subprocess
            subprocess.run(cmd, shell=True)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "SEC_SUBPROCESS_SHELL_001"
        assert findings[0].metadata["function"] == "subprocess.run"
        assert findings[0].severity == Severity.HIGH

    def test_subprocess_call_shell(self, analyzer, temp_repo):
        """Detect subprocess.call with shell=True."""
        write_py(temp_repo, "app.py", """
            import subprocess
            subprocess.call("ls -la", shell=True)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["function"] == "subprocess.call"

    def test_subprocess_popen_shell(self, analyzer, temp_repo):
        """Detect subprocess.Popen with shell=True."""
        write_py(temp_repo, "app.py", """
            import subprocess
            p = subprocess.Popen(cmd, shell=True)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["function"] == "subprocess.Popen"

    def test_os_system_detected(self, analyzer, temp_repo):
        """Detect os.system() which is inherently shell-based."""
        write_py(temp_repo, "app.py", """
            import os
            os.system(cmd)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["function"] == "os.system"


# ============================================================================
# SEC_SQL_INJECTION_001 — SQL string formatting
# ============================================================================

class TestSqlInjectionDetected:
    """Tests for SEC_SQL_INJECTION_001 rule."""

    def test_sql_fstring_format(self, analyzer, temp_repo):
        """Detect SQL query with f-string formatting."""
        write_py(temp_repo, "app.py", '''
            query = f"SELECT * FROM users WHERE id = {user_id}"
        ''')
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "SEC_SQL_INJECTION_001"
        assert findings[0].severity == Severity.CRITICAL

    def test_sql_percent_format(self, analyzer, temp_repo):
        """Detect SQL query with % formatting."""
        write_py(temp_repo, "app.py", '''
            query = "SELECT * FROM users WHERE name = '%s'" % name
        ''')
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1

    def test_sql_format_method(self, analyzer, temp_repo):
        """Detect SQL query with .format() method."""
        write_py(temp_repo, "app.py", '''
            query = "DELETE FROM {} WHERE id = {}".format(table, id)
        ''')
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1

    def test_sql_concatenation(self, analyzer, temp_repo):
        """Detect SQL query with string concatenation."""
        write_py(temp_repo, "app.py", '''
            query = "INSERT INTO users VALUES ('" + user_input + "')"
        ''')
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1


# ============================================================================
# SEC_PICKLE_LOAD_001 — unsafe deserialization
# ============================================================================

class TestPickleLoadDetected:
    """Tests for SEC_PICKLE_LOAD_001 rule."""

    def test_pickle_load(self, analyzer, temp_repo):
        """Detect pickle.load() usage."""
        write_py(temp_repo, "app.py", """
            import pickle
            data = pickle.load(f)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "SEC_PICKLE_LOAD_001"
        assert findings[0].metadata["function"] == "pickle.load"
        assert findings[0].severity == Severity.HIGH

    def test_pickle_loads(self, analyzer, temp_repo):
        """Detect pickle.loads() usage."""
        write_py(temp_repo, "app.py", """
            import pickle
            data = pickle.loads(raw_bytes)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["function"] == "pickle.loads"


# ============================================================================
# SEC_YAML_UNSAFE_001 — unsafe YAML loading
# ============================================================================

class TestYamlUnsafeDetected:
    """Tests for SEC_YAML_UNSAFE_001 rule."""

    def test_yaml_load_no_loader(self, analyzer, temp_repo):
        """Detect yaml.load() without explicit Loader."""
        write_py(temp_repo, "app.py", """
            import yaml
            data = yaml.load(content)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "SEC_YAML_UNSAFE_001"
        assert findings[0].severity == Severity.HIGH

    def test_yaml_unsafe_load(self, analyzer, temp_repo):
        """Detect yaml.unsafe_load() usage."""
        write_py(temp_repo, "app.py", """
            import yaml
            data = yaml.unsafe_load(content)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 1
        assert findings[0].metadata["function"] == "yaml.unsafe_load"


# ============================================================================
# Negative cases — no false positives
# ============================================================================

class TestNoFalsePositives:
    """Tests for patterns that should NOT be flagged."""

    def test_env_var_password(self, analyzer, temp_repo):
        """Password from env var is not flagged."""
        write_py(temp_repo, "app.py", """
            import os
            password = os.getenv("PASSWORD")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        secret_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_HARDCODED_SECRET_001"]
        assert len(secret_findings) == 0

    def test_empty_password(self, analyzer, temp_repo):
        """Empty password string is not flagged."""
        write_py(temp_repo, "app.py", """
            password = ""
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        secret_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_HARDCODED_SECRET_001"]
        assert len(secret_findings) == 0

    def test_subprocess_no_shell(self, analyzer, temp_repo):
        """subprocess.run without shell=True is not flagged."""
        write_py(temp_repo, "app.py", """
            import subprocess
            subprocess.run(["ls", "-la"])
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        shell_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_SUBPROCESS_SHELL_001"]
        assert len(shell_findings) == 0

    def test_parameterized_sql(self, analyzer, temp_repo):
        """Parameterized SQL query is not flagged."""
        write_py(temp_repo, "app.py", """
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        sql_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_SQL_INJECTION_001"]
        assert len(sql_findings) == 0

    def test_yaml_safe_load(self, analyzer, temp_repo):
        """yaml.safe_load() is not flagged."""
        write_py(temp_repo, "app.py", """
            import yaml
            data = yaml.safe_load(content)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        yaml_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_YAML_UNSAFE_001"]
        assert len(yaml_findings) == 0

    def test_yaml_load_with_safeloader(self, analyzer, temp_repo):
        """yaml.load() with SafeLoader is not flagged."""
        write_py(temp_repo, "app.py", """
            import yaml
            data = yaml.load(content, Loader=yaml.SafeLoader)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        yaml_findings = [f for f in findings if f.metadata.get("rule_id") == "SEC_YAML_UNSAFE_001"]
        assert len(yaml_findings) == 0

    def test_clean_file(self, analyzer, temp_repo):
        """Clean file has no findings."""
        write_py(temp_repo, "app.py", """
            import os

            def get_config():
                return {
                    "api_key": os.getenv("API_KEY"),
                    "debug": False,
                }
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert len(findings) == 0


# ============================================================================
# Integration with fixtures
# ============================================================================

class TestFixtureRepos:
    """Tests using fixture repos."""

    def test_security_hot_fixture(self, analyzer):
        """Fixture with all security patterns is detected."""
        fixture_path = Path(__file__).parent / "fixtures" / "repos" / "security_hot"
        if not fixture_path.exists():
            pytest.skip("Fixture not created yet")

        src_path = fixture_path / "src" / "app.py"
        findings = analyzer.run(fixture_path, [src_path])

        # Should detect all 6 rule types
        rule_ids = {f.metadata["rule_id"] for f in findings}
        assert "SEC_HARDCODED_SECRET_001" in rule_ids
        assert "SEC_EVAL_001" in rule_ids
        assert "SEC_SUBPROCESS_SHELL_001" in rule_ids
        assert "SEC_SQL_INJECTION_001" in rule_ids
        assert "SEC_PICKLE_LOAD_001" in rule_ids
        assert "SEC_YAML_UNSAFE_001" in rule_ids

    def test_security_clean_fixture(self, analyzer):
        """Clean fixture has no findings."""
        fixture_path = Path(__file__).parent / "fixtures" / "repos" / "security_clean"
        if not fixture_path.exists():
            pytest.skip("Fixture not created yet")

        src_path = fixture_path / "src" / "app.py"
        findings = analyzer.run(fixture_path, [src_path])

        assert len(findings) == 0


# ============================================================================
# Signal integration
# ============================================================================

class TestSecuritySignal:
    """Tests for security signal translation."""

    def test_signal_aggregation(self, analyzer, temp_repo):
        """Security findings aggregate into one signal."""
        from code_audit.insights.translator import findings_to_signals

        write_py(temp_repo, "app.py", """
            password = "secret123"
            result = eval(user_input)
            import subprocess
            subprocess.run(cmd, shell=True)
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])
        signals = findings_to_signals(findings)

        assert len(signals) == 1
        assert signals[0]["type"] == "security"
        assert "hardcoded_secret_count" in signals[0]["evidence"]["summary"]
        assert "eval_exec_count" in signals[0]["evidence"]["summary"]
        assert "subprocess_shell_count" in signals[0]["evidence"]["summary"]

    def test_no_signal_when_clean(self, analyzer, temp_repo):
        """Clean file produces no security signal."""
        from code_audit.insights.translator import findings_to_signals

        write_py(temp_repo, "app.py", """
            import os
            password = os.getenv("PASSWORD")
        """)
        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])
        signals = findings_to_signals(findings)

        assert len(signals) == 0


# ============================================================================
# API integration
# ============================================================================

class TestAPIIntegration:
    """Tests for API integration."""

    def test_scan_project_includes_security(self, temp_repo):
        """scan_project includes security findings."""
        from code_audit.api import scan_project

        write_py(temp_repo, "app.py", """
            password = "hardcoded"
        """)

        _, result = scan_project(temp_repo, ci_mode=True)

        # Check findings include security type
        findings = result.get("findings_raw", [])
        security_findings = [f for f in findings if f.get("type") == "security"]
        assert len(security_findings) >= 1

    def test_clean_repo_has_no_security_issues(self, temp_repo):
        """Clean repo has no security findings."""
        from code_audit.api import scan_project

        write_py(temp_repo, "app.py", """
            import os

            def get_password():
                return os.getenv("PASSWORD")
        """)

        _, result = scan_project(temp_repo, ci_mode=True)

        findings = result.get("findings_raw", [])
        security_findings = [f for f in findings if f.get("type") == "security"]
        assert len(security_findings) == 0


# ============================================================================
# Determinism
# ============================================================================

class TestDeterminism:
    """Tests for deterministic output."""

    def test_stable_finding_ids(self, analyzer, temp_repo):
        """Finding IDs are stable across runs."""
        write_py(temp_repo, "app.py", """
            password = "secret123"
        """)

        findings1 = analyzer.run(temp_repo, [temp_repo / "app.py"])
        findings2 = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert findings1[0].finding_id == findings2[0].finding_id
        assert findings1[0].fingerprint == findings2[0].fingerprint

    def test_posix_paths(self, analyzer, temp_repo):
        """Paths are POSIX-style (forward slashes)."""
        write_py(temp_repo, "app.py", """
            password = "secret123"
        """)

        findings = analyzer.run(temp_repo, [temp_repo / "app.py"])

        assert "\\" not in findings[0].location.path
