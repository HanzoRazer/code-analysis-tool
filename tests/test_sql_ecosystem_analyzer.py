"""Tests for SQL Ecosystem Analyzer."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from code_audit.analyzers.sql_ecosystem import (
    MigrationValidator,
    ORMValidator,
    PerformanceValidator,
    PythonSQLInjectionValidator,
    SchemaValidator,
    SecurityValidator,
    SQLAnalyzerConfig,
    SQLEcosystemAnalyzer,
    SyntaxValidator,
    analyze_sql_project,
    check_sql_injection,
)
from code_audit.model import Severity


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project structure."""
    (tmp_path / "sql").mkdir()
    (tmp_path / "models").mkdir()
    (tmp_path / "migrations").mkdir()
    return tmp_path


@pytest.fixture
def config() -> SQLAnalyzerConfig:
    """Default test configuration."""
    return SQLAnalyzerConfig()


# ============================================================================
# TEST: SQLAnalyzerConfig
# ============================================================================

class TestSQLAnalyzerConfig:
    """Test configuration loading and discovery."""

    def test_default_config(self):
        config = SQLAnalyzerConfig()
        assert config.dialect == "postgresql"
        assert "syntax" in config.enabled_validators
        assert "security" in config.enabled_validators

    def test_load_yaml_config(self, tmp_path: Path):
        config_file = tmp_path / ".sql-analyzer.yaml"
        config_file.write_text("""
dialect: mysql
validators:
  - syntax
  - security
severity_threshold: HIGH
""")
        config = SQLAnalyzerConfig.load(config_file)
        assert config.dialect == "mysql"
        assert config.enabled_validators == {"syntax", "security"}
        assert config.severity_threshold == Severity.HIGH

    def test_discover_config(self, tmp_path: Path):
        config_file = tmp_path / ".sql-analyzer.yaml"
        config_file.write_text("dialect: sqlite")

        config = SQLAnalyzerConfig.discover(tmp_path)
        assert config.dialect == "sqlite"

    def test_discover_missing_config(self, tmp_path: Path):
        config = SQLAnalyzerConfig.discover(tmp_path)
        assert config.dialect == "postgresql"  # Default


# ============================================================================
# TEST: SyntaxValidator
# ============================================================================

class TestSyntaxValidator:
    """Test SQL syntax error detection."""

    def test_valid_sql(self, tmp_path: Path):
        validator = SyntaxValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT id, name FROM users WHERE active = 1;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert len(findings) == 0

    def test_missing_columns_after_select(self, tmp_path: Path):
        validator = SyntaxValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT FROM users;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("SELECT without columns" in f.message for f in findings)

    def test_unbalanced_parentheses(self, tmp_path: Path):
        validator = SyntaxValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT * FROM users WHERE (active = 1 AND role = 'admin';"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("parentheses" in f.message.lower() for f in findings)

    def test_unclosed_quote(self, tmp_path: Path):
        validator = SyntaxValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT * FROM users WHERE name = 'John;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("quote" in f.message.lower() for f in findings)

    def test_where_leading_and(self, tmp_path: Path):
        validator = SyntaxValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT * FROM users WHERE AND active = 1;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("leading AND" in f.message for f in findings)


# ============================================================================
# TEST: SecurityValidator
# ============================================================================

class TestSecurityValidator:
    """Test SQL security vulnerability detection."""

    def test_dynamic_sql_concatenation(self, tmp_path: Path):
        validator = SecurityValidator()
        config = SQLAnalyzerConfig()

        sql = "EXEC ('SELECT * FROM users WHERE id = ' + @user_input)"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("injection" in f.message.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_grant_all_privileges(self, tmp_path: Path):
        validator = SecurityValidator()
        config = SQLAnalyzerConfig()

        sql = "GRANT ALL PRIVILEGES ON database.* TO 'user'@'%';"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("privilege" in f.message.lower() for f in findings)

    def test_grant_to_public(self, tmp_path: Path):
        validator = SecurityValidator()
        config = SQLAnalyzerConfig()

        sql = "GRANT SELECT ON users TO PUBLIC;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("PUBLIC" in f.message for f in findings)

    def test_delete_without_where(self, tmp_path: Path):
        validator = SecurityValidator()
        config = SQLAnalyzerConfig()

        sql = "DELETE FROM users;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("DELETE without WHERE" in f.message for f in findings)

    def test_safe_delete_with_where(self, tmp_path: Path):
        validator = SecurityValidator()
        config = SQLAnalyzerConfig()

        sql = "DELETE FROM users WHERE id = 123;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        # Should not flag safe DELETE
        assert not any("DELETE without WHERE" in f.message for f in findings)


# ============================================================================
# TEST: PythonSQLInjectionValidator
# ============================================================================

class TestPythonSQLInjectionValidator:
    """Test SQL injection detection in Python code."""

    def test_fstring_execute(self, tmp_path: Path):
        validator = PythonSQLInjectionValidator()
        config = SQLAnalyzerConfig()

        code = '''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        file_path = tmp_path / "test.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("f-string" in f.message.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_format_execute(self, tmp_path: Path):
        validator = PythonSQLInjectionValidator()
        config = SQLAnalyzerConfig()

        code = '''
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
'''
        file_path = tmp_path / "test.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("format" in f.message.lower() for f in findings)

    def test_concatenation_execute(self, tmp_path: Path):
        validator = PythonSQLInjectionValidator()
        config = SQLAnalyzerConfig()

        code = '''
cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
'''
        file_path = tmp_path / "test.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("concatenation" in f.message.lower() for f in findings)

    def test_percent_execute(self, tmp_path: Path):
        validator = PythonSQLInjectionValidator()
        config = SQLAnalyzerConfig()

        code = '''
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
'''
        file_path = tmp_path / "test.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("%" in f.message for f in findings)

    def test_safe_parameterized_query(self, tmp_path: Path):
        validator = PythonSQLInjectionValidator()
        config = SQLAnalyzerConfig()

        code = '''
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
'''
        file_path = tmp_path / "test.py"

        findings = validator.validate(code, file_path, config, {})
        # Should not flag parameterized queries
        injection_findings = [f for f in findings if "injection" in f.metadata.get('rule_id', '')]
        assert len(injection_findings) == 0

    def test_skip_non_python_files(self, tmp_path: Path):
        validator = PythonSQLInjectionValidator()
        config = SQLAnalyzerConfig()

        code = "SELECT * FROM users WHERE id = {user_id}"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(code, file_path, config, {})
        assert len(findings) == 0


# ============================================================================
# TEST: PerformanceValidator
# ============================================================================

class TestPerformanceValidator:
    """Test query performance issue detection."""

    def test_select_star(self, tmp_path: Path):
        validator = PerformanceValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT * FROM users WHERE active = 1;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("SELECT *" in f.message for f in findings)

    def test_explicit_columns_ok(self, tmp_path: Path):
        validator = PerformanceValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT id, name, email FROM users WHERE active = 1;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert not any("SELECT *" in f.message for f in findings)

    def test_like_leading_wildcard(self, tmp_path: Path):
        validator = PerformanceValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT * FROM users WHERE name LIKE '%john%';"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("LIKE" in f.message and "wildcard" in f.message for f in findings)

    def test_like_trailing_wildcard_ok(self, tmp_path: Path):
        validator = PerformanceValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT * FROM users WHERE name LIKE 'john%';"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        # Trailing wildcard is OK
        assert not any("leading wildcard" in f.message for f in findings)

    def test_implicit_cross_join(self, tmp_path: Path):
        validator = PerformanceValidator()
        config = SQLAnalyzerConfig()

        sql = "SELECT * FROM users, orders WHERE users.id = orders.user_id;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("cross join" in f.message.lower() for f in findings)

    def test_n_plus_one_pattern(self, tmp_path: Path):
        validator = PerformanceValidator()
        config = SQLAnalyzerConfig()

        code = '''
for user in users:
    cursor.execute("SELECT * FROM orders WHERE user_id = %s", (user.id,))
'''
        file_path = tmp_path / "test.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("N+1" in f.message for f in findings)


# ============================================================================
# TEST: SchemaValidator
# ============================================================================

class TestSchemaValidator:
    """Test schema definition validation."""

    def test_missing_primary_key(self, tmp_path: Path):
        validator = SchemaValidator()
        config = SQLAnalyzerConfig()

        sql = """
CREATE TABLE users (
    name VARCHAR(255),
    email VARCHAR(255)
);
"""
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("primary key" in f.message.lower() for f in findings)

    def test_has_primary_key_ok(self, tmp_path: Path):
        validator = SchemaValidator()
        config = SQLAnalyzerConfig()

        sql = """
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255)
);
"""
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert not any("primary key" in f.message.lower() for f in findings)

    def test_varchar_without_length(self, tmp_path: Path):
        validator = SchemaValidator()
        config = SQLAnalyzerConfig()

        sql = """
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR
);
"""
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("VARCHAR without length" in f.message for f in findings)

    def test_reserved_word_table_name(self, tmp_path: Path):
        validator = SchemaValidator()
        config = SQLAnalyzerConfig()

        sql = "CREATE TABLE user (id SERIAL PRIMARY KEY);"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("reserved word" in f.message.lower() for f in findings)

    def test_missing_audit_columns(self, tmp_path: Path):
        validator = SchemaValidator()
        config = SQLAnalyzerConfig(required_audit_columns=["created_at", "updated_at"])

        sql = """
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255)
);
"""
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("created_at" in f.message for f in findings)
        assert any("updated_at" in f.message for f in findings)


# ============================================================================
# TEST: MigrationValidator
# ============================================================================

class TestMigrationValidator:
    """Test migration validation."""

    def test_valid_migration_name_timestamp(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        file_path = tmp_path / "20250215123045_add_users.sql"
        file_path.write_text("CREATE TABLE users (id INT);")

        findings = validator.validate(file_path.read_text(), file_path, config, {})
        assert not any("naming" in f.metadata.get('rule_id', '') for f in findings)

    def test_valid_migration_name_flyway(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        file_path = tmp_path / "V1__initial_schema.sql"
        file_path.write_text("CREATE TABLE users (id INT);")

        findings = validator.validate(file_path.read_text(), file_path, config, {})
        assert not any("naming" in f.metadata.get('rule_id', '') for f in findings)

    def test_invalid_migration_name(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        file_path = tmp_path / "add_users.sql"
        file_path.write_text("CREATE TABLE users (id INT);")

        findings = validator.validate(file_path.read_text(), file_path, config, {})
        assert any("naming" in f.metadata.get('rule_id', '') for f in findings)

    def test_breaking_change_drop_table(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        sql = "DROP TABLE users;"
        file_path = tmp_path / "20250215_drop_users.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("breaking" in f.metadata.get('rule_id', '') for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_breaking_change_drop_column(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        sql = "ALTER TABLE users DROP COLUMN email;"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("breaking" in f.metadata.get('rule_id', '') for f in findings)

    def test_missing_rollback(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        sql = """
-- Migration: Add users table
CREATE TABLE users (id INT);
"""
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("rollback" in f.message.lower() for f in findings)

    def test_has_rollback_ok(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        sql = """
-- Up
CREATE TABLE users (id INT);

-- Down
DROP TABLE users;
"""
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert not any("rollback" in f.message.lower() for f in findings)

    def test_mixed_ddl_dml(self, tmp_path: Path):
        validator = MigrationValidator()
        config = SQLAnalyzerConfig()

        sql = """
CREATE TABLE users (id INT);
INSERT INTO users (id) VALUES (1);
"""
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert any("DDL" in f.message and "DML" in f.message for f in findings)


# ============================================================================
# TEST: ORMValidator
# ============================================================================

class TestORMValidator:
    """Test ORM model validation."""

    def test_sqlalchemy_missing_primary_key(self, tmp_path: Path):
        validator = ORMValidator()
        config = SQLAnalyzerConfig()

        code = '''
class User(Base):
    __tablename__ = 'users'
    name = Column(String(255))
'''
        file_path = tmp_path / "models.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("primary key" in f.message.lower() for f in findings)

    def test_sqlalchemy_has_primary_key_ok(self, tmp_path: Path):
        validator = ORMValidator()
        config = SQLAnalyzerConfig()

        code = '''
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
'''
        file_path = tmp_path / "models.py"

        findings = validator.validate(code, file_path, config, {})
        assert not any("primary key" in f.message.lower() for f in findings)

    def test_sqlalchemy_string_without_length(self, tmp_path: Path):
        validator = ORMValidator()
        config = SQLAnalyzerConfig()

        code = '''
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String())
'''
        file_path = tmp_path / "models.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("String without length" in f.message for f in findings)

    def test_django_charfield_no_max_length(self, tmp_path: Path):
        validator = ORMValidator()
        config = SQLAnalyzerConfig()

        code = '''
class User(models.Model):
    name = models.CharField()
'''
        file_path = tmp_path / "models.py"

        findings = validator.validate(code, file_path, config, {})
        assert any("max_length" in f.message for f in findings)

    def test_skip_non_python(self, tmp_path: Path):
        validator = ORMValidator()
        config = SQLAnalyzerConfig()

        sql = "CREATE TABLE users (id INT);"
        file_path = tmp_path / "test.sql"

        findings = validator.validate(sql, file_path, config, {})
        assert len(findings) == 0


# ============================================================================
# TEST: SQLEcosystemAnalyzer (Integration)
# ============================================================================

class TestSQLEcosystemAnalyzer:
    """Test main analyzer orchestration."""

    def test_from_root_auto_config(self, tmp_path: Path):
        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        assert analyzer.config.dialect == "postgresql"

    def test_run_sql_files(self, tmp_path: Path):
        # Create test SQL file
        sql_file = tmp_path / "test.sql"
        sql_file.write_text("SELECT * FROM users;")

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        findings = analyzer.run(tmp_path, [sql_file])

        # Should find SELECT *
        assert any("SELECT *" in f.message for f in findings)

    def test_run_python_files(self, tmp_path: Path):
        # Create test Python file
        py_file = tmp_path / "test.py"
        py_file.write_text('''
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
''')

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        findings = analyzer.run(tmp_path, [py_file])

        # Should find injection - check message or rule_id
        assert any(
            "injection" in f.message.lower() or 
            "injection" in f.metadata.get('rule_id', '') or 
            "fstring" in f.metadata.get('rule_id', '')
            for f in findings
        )

    def test_scan_directory(self, tmp_path: Path):
        # Create files
        (tmp_path / "schema.sql").write_text("CREATE TABLE t (id INT);")
        (tmp_path / "models.py").write_text("class User: pass")

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        files = analyzer.scan_directory(tmp_path)

        assert any(f.suffix == ".sql" for f in files)
        assert any(f.suffix == ".py" for f in files)

    def test_severity_threshold_filter(self, tmp_path: Path):
        sql_file = tmp_path / "test.sql"
        sql_file.write_text("SELECT * FROM users;")  # MEDIUM severity

        # Set threshold to HIGH
        config = SQLAnalyzerConfig(severity_threshold=Severity.HIGH)
        analyzer = SQLEcosystemAnalyzer(config)

        findings = analyzer.run(tmp_path, [sql_file])

        # MEDIUM findings should be filtered
        assert not any(f.severity == Severity.MEDIUM for f in findings)

    def test_register_custom_validator(self):
        from code_audit.analyzers.sql_ecosystem import BaseSQLValidator

        class CustomValidator(BaseSQLValidator):
            id = "custom"

            def validate(self, content, file_path, config, context):
                return []

        SQLEcosystemAnalyzer.register_validator(CustomValidator)
        assert "custom" in SQLEcosystemAnalyzer._BUILTIN_VALIDATORS


# ============================================================================
# TEST: Convenience Functions
# ============================================================================

class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_analyze_sql_project(self, tmp_path: Path):
        (tmp_path / "test.sql").write_text("SELECT * FROM users;")

        findings = analyze_sql_project(tmp_path)
        assert isinstance(findings, list)

    def test_check_sql_injection(self, tmp_path: Path):
        py_file = tmp_path / "test.py"
        py_file.write_text('''
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
''')

        findings = check_sql_injection(py_file)
        assert any("injection" in f.metadata.get('rule_id', '') or "fstring" in f.metadata.get('rule_id', '') for f in findings)


# ============================================================================
# TEST: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        sql_file = tmp_path / "empty.sql"
        sql_file.write_text("")

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        findings = analyzer.run(tmp_path, [sql_file])
        assert len(findings) == 0

    def test_binary_file_handling(self, tmp_path: Path):
        bin_file = tmp_path / "test.sql"
        bin_file.write_bytes(b"\x00\x01\x02\x03")

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        findings = analyzer.run(tmp_path, [bin_file])
        # Should handle gracefully
        assert isinstance(findings, list)

    def test_very_long_line(self, tmp_path: Path):
        long_sql = "SELECT " + "a, " * 1000 + "b FROM users;"
        sql_file = tmp_path / "long.sql"
        sql_file.write_text(long_sql)

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        findings = analyzer.run(tmp_path, [sql_file])
        # Should not crash
        assert isinstance(findings, list)

    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason="Unicode encoding issues on Windows cp1252"
    )
    def test_unicode_content(self, tmp_path: Path):
        sql_file = tmp_path / "unicode.sql"
        sql_file.write_text("SELECT * FROM users WHERE name = '中文';")

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        findings = analyzer.run(tmp_path, [sql_file])
        assert isinstance(findings, list)

    def test_python_syntax_error_handling(self, tmp_path: Path):
        py_file = tmp_path / "broken.py"
        py_file.write_text("def broken(:\n    pass")

        analyzer = SQLEcosystemAnalyzer.from_root(tmp_path)
        findings = analyzer.run(tmp_path, [py_file])
        # Should handle gracefully
        assert isinstance(findings, list)
