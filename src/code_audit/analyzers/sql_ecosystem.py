"""
SQL Ecosystem Analyzer
=======================
Comprehensive SQL code analysis: syntax, schema, queries, security, migrations, ORM.

Follows the Analyzer protocol and integrates with code_audit infrastructure.

Usage:
    analyzer = SQLEcosystemAnalyzer.from_root(project_path)
    findings = analyzer.run(project_path, sql_files)

Configuration via .sql-analyzer.yaml or inline:
    dialect: postgresql
    validators:
      - syntax
      - security
      - performance
      - schema
      - migration
      - orm
    severity_threshold: medium
"""

from __future__ import annotations

import ast
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Protocol, Set, Type

import yaml

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class SQLAnalyzerConfig:
    """Configuration for SQL ecosystem analysis."""

    # SQL dialect for parsing
    dialect: str = "postgresql"

    # Which validators to run
    enabled_validators: Set[str] = field(default_factory=lambda: {
        "syntax", "security", "performance", "schema", "migration", "orm", "injection"
    })

    # File patterns to analyze
    sql_patterns: List[str] = field(default_factory=lambda: [
        "**/*.sql", "**/*.prc", "**/*.fnc", "**/*.trg"
    ])
    orm_patterns: List[str] = field(default_factory=lambda: [
        "**/models/**/*.py", "**/models.py", "**/schemas.py"
    ])
    migration_patterns: List[str] = field(default_factory=lambda: [
        "**/migrations/**/*.sql", "**/migrations/**/*.py",
        "**/alembic/**/*.py", "**/flyway/**/*.sql"
    ])

    # Severity threshold (findings below this are filtered)
    severity_threshold: Severity = Severity.LOW

    # SQL injection detection in Python
    python_sql_patterns: List[str] = field(default_factory=lambda: [
        "**/*.py"
    ])

    # Custom rules
    required_audit_columns: List[str] = field(default_factory=lambda: [
        "created_at", "updated_at"
    ])
    max_query_complexity: int = 10

    @classmethod
    def load(cls, config_path: Path) -> "SQLAnalyzerConfig":
        """Load config from YAML file."""
        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        return cls(
            dialect=data.get("dialect", "postgresql"),
            enabled_validators=set(data.get("validators", cls().enabled_validators)),
            sql_patterns=data.get("sql_patterns", cls().sql_patterns),
            severity_threshold=Severity[data.get("severity_threshold", "LOW").upper()],
        )

    @classmethod
    def discover(cls, root: Path) -> "SQLAnalyzerConfig":
        """Auto-discover configuration from project root."""
        config_files = [
            root / ".sql-analyzer.yaml",
            root / ".sql-analyzer.yml",
            root / "sql-analyzer.yaml",
        ]

        for config_file in config_files:
            if config_file.exists():
                return cls.load(config_file)

        return cls()


# ============================================================================
# VALIDATOR PROTOCOL & BASE
# ============================================================================

class SQLValidatorProtocol(Protocol):
    """Protocol for SQL validators."""

    id: str

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        """Validate SQL content and return findings."""
        ...


class BaseSQLValidator(ABC):
    """Base class for SQL validators with common utilities."""

    id: ClassVar[str]

    @abstractmethod
    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        """Validate content and return findings."""
        ...

    def _make_finding(
        self,
        severity: Severity,
        message: str,
        file_path: Path,
        line: int = 0,
        column: int = 0,
        snippet: str = "",
        recommendation: str = "",
        rule_id: str = "",
        auto_fixable: bool = False,
        confidence: float = 0.9,
    ) -> Finding:
        """Create a Finding with standard formatting."""
        rule = rule_id or self.id
        rel_path = str(file_path)
        snippet_text = snippet[:200] if snippet else ""
        
        return Finding(
            finding_id=f"sql_{self.id}_{rule}_{line}",
            type=AnalyzerType.SQL,
            severity=severity,
            confidence=confidence,
            message=f"{message}. {recommendation}" if recommendation else message,
            location=Location(path=rel_path, line_start=line, line_end=line),
            fingerprint=make_fingerprint(rule, rel_path, "", snippet_text),
            snippet=snippet_text,
            metadata={
                "rule_id": rule,
                "auto_fixable": auto_fixable,
                "recommendation": recommendation,
            },
        )

    def _get_line_number(self, content: str, position: int) -> int:
        """Get line number from character position."""
        return content[:position].count('\n') + 1

    def _get_line_at(self, content: str, line_num: int) -> str:
        """Get content of specific line."""
        lines = content.split('\n')
        if 0 < line_num <= len(lines):
            return lines[line_num - 1]
        return ""


# ============================================================================
# SYNTAX VALIDATOR
# ============================================================================

class SyntaxValidator(BaseSQLValidator):
    """Detects SQL syntax errors."""

    id = "syntax"

    # Common syntax error patterns
    ERROR_PATTERNS = [
        (r"SELECT\s+FROM", "SELECT without columns"),
        (r"FROM\s+WHERE", "FROM without table"),
        (r"INSERT\s+VALUES", "INSERT missing INTO"),
        (r"UPDATE\s+SET", "UPDATE missing table name"),
        (r"DELETE\s+WHERE", "DELETE missing FROM"),
        (r"ORDER\s+BY\s*$", "ORDER BY without columns"),
        (r"GROUP\s+BY\s*$", "GROUP BY without columns"),
        (r"WHERE\s+AND", "WHERE with leading AND"),
        (r"WHERE\s+OR", "WHERE with leading OR"),
    ]

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        findings = []

        # Try parsing with sqlglot if available
        findings.extend(self._check_parse_errors(content, file_path, config))

        # Pattern-based checks
        findings.extend(self._check_syntax_patterns(content, file_path))

        # Structural checks
        findings.extend(self._check_parentheses(content, file_path))
        findings.extend(self._check_quotes(content, file_path))

        return findings

    def _check_parse_errors(
        self, content: str, file_path: Path, config: SQLAnalyzerConfig
    ) -> List[Finding]:
        """Check for parse errors using sqlglot."""
        findings = []

        try:
            from sqlglot import parse
            from sqlglot.errors import ParseError

            try:
                parse(content, dialect=config.dialect)
            except ParseError as e:
                line_match = re.search(r"line (\d+)", str(e))
                line_num = int(line_match.group(1)) if line_match else 1

                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message=f"SQL parse error: {e}",
                    file_path=file_path,
                    line=line_num,
                    snippet=self._get_line_at(content, line_num),
                    recommendation="Fix SQL syntax based on error message",
                    rule_id="parse_error",
                ))
        except ImportError:
            # sqlglot not available, skip parse checking
            pass

        return findings

    def _check_syntax_patterns(self, content: str, file_path: Path) -> List[Finding]:
        """Check for common syntax error patterns."""
        findings = []

        for pattern, description in self.ERROR_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message=f"Syntax error: {description}",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group(),
                    recommendation=f"Fix: {description}",
                    rule_id="syntax_pattern",
                ))

        return findings

    def _check_parentheses(self, content: str, file_path: Path) -> List[Finding]:
        """Check for unbalanced parentheses."""
        findings = []
        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Skip if in string literal (simple check)
            if self._is_likely_string_content(line):
                continue

            open_count = line.count('(')
            close_count = line.count(')')

            if open_count != close_count:
                findings.append(self._make_finding(
                    severity=Severity.MEDIUM,
                    message=f"Unbalanced parentheses: {open_count} open, {close_count} close",
                    file_path=file_path,
                    line=i,
                    snippet=line.strip(),
                    recommendation="Ensure all parentheses are properly closed",
                    rule_id="unbalanced_parens",
                ))

        return findings

    def _check_quotes(self, content: str, file_path: Path) -> List[Finding]:
        """Check for unclosed quotes."""
        findings = []
        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Count quotes (excluding escaped)
            single_quotes = len(re.findall(r"(?<!\\)'", line))

            if single_quotes % 2 != 0:
                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message="Unclosed single quote",
                    file_path=file_path,
                    line=i,
                    snippet=line.strip(),
                    recommendation="Close the string literal with matching quote",
                    rule_id="unclosed_quote",
                ))

        return findings

    def _is_likely_string_content(self, line: str) -> bool:
        """Check if line is likely inside a multi-line string."""
        stripped = line.strip()
        return stripped.startswith("'") or stripped.startswith('"')


# ============================================================================
# SECURITY VALIDATOR (SQL INJECTION)
# ============================================================================

class SecurityValidator(BaseSQLValidator):
    """Scans for SQL security vulnerabilities."""

    id = "security"

    # SQL injection patterns in SQL files
    SQL_INJECTION_PATTERNS = [
        (r"EXEC\s*\(\s*['\"].*\+", "Dynamic SQL with concatenation"),
        (r"EXECUTE\s+IMMEDIATE\s+.*\|\|", "Oracle dynamic SQL concatenation"),
        (r"sp_executesql\s+.*\+", "SQL Server dynamic SQL concatenation"),
        (r"PREPARE\s+.*FROM\s+.*\|\|", "Prepared statement from concatenation"),
    ]

    # Dangerous privilege patterns
    PRIVILEGE_PATTERNS = [
        (r"GRANT\s+ALL\s+PRIVILEGES", "Grants all privileges"),
        (r"GRANT\s+.*\s+TO\s+PUBLIC", "Grants to PUBLIC role"),
        (r"ALTER\s+USER.*SUPERUSER", "Superuser privilege grant"),
        (r"GRANT\s+.*\s+WITH\s+GRANT\s+OPTION", "Privilege with grant option"),
    ]

    # Dangerous operations
    DANGEROUS_PATTERNS = [
        (r"DROP\s+DATABASE", "Drops entire database"),
        (r"TRUNCATE\s+TABLE", "Truncates table without WHERE"),
        (r"DELETE\s+FROM\s+\w+\s*;", "DELETE without WHERE clause"),
        (r"UPDATE\s+\w+\s+SET\s+.*(?!WHERE)", "UPDATE without WHERE clause"),
    ]

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        findings = []

        # Check for SQL injection patterns
        for pattern, description in self.SQL_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message=f"SQL injection risk: {description}",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group()[:100],
                    recommendation="Use parameterized queries or prepared statements",
                    rule_id="sql_injection",
                ))

        # Check for privilege issues
        for pattern, description in self.PRIVILEGE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.MEDIUM,
                    message=f"Excessive privileges: {description}",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group(),
                    recommendation="Apply principle of least privilege",
                    rule_id="excessive_privilege",
                ))

        # Check for dangerous operations
        for pattern, description in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message=f"Dangerous operation: {description}",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group(),
                    recommendation="Add WHERE clause or verify this is intentional",
                    rule_id="dangerous_operation",
                ))

        return findings


# ============================================================================
# PYTHON SQL INJECTION VALIDATOR
# ============================================================================

class PythonSQLInjectionValidator(BaseSQLValidator):
    """Detects SQL injection patterns in Python code."""

    id = "injection"

    # Patterns for dynamic SQL construction
    FSTRING_SQL_PATTERN = re.compile(
        r'f["\'].*?(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*?\{',
        re.IGNORECASE
    )
    FORMAT_SQL_PATTERN = re.compile(
        r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\.format\(',
        re.IGNORECASE
    )
    CONCAT_SQL_PATTERN = re.compile(
        r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?["\']\s*\+',
        re.IGNORECASE
    )
    PERCENT_SQL_PATTERN = re.compile(
        r'["\'].*?(SELECT|INSERT|UPDATE|DELETE).*?%s.*?["\']',
        re.IGNORECASE
    )

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        # Only process Python files
        if file_path.suffix != '.py':
            return []

        findings = []

        try:
            tree = ast.parse(content)
            findings.extend(self._analyze_ast(tree, content, file_path))
        except SyntaxError:
            # Skip files with Python syntax errors
            pass

        # Also do regex-based detection for edge cases
        findings.extend(self._regex_detection(content, file_path))

        return findings

    def _analyze_ast(
        self, tree: ast.AST, content: str, file_path: Path
    ) -> List[Finding]:
        """Analyze Python AST for SQL injection patterns."""
        findings = []

        for node in ast.walk(tree):
            # Check cursor.execute() calls
            if isinstance(node, ast.Call):
                findings.extend(self._check_execute_call(node, content, file_path))

            # Check f-strings with SQL keywords
            if isinstance(node, ast.JoinedStr):
                findings.extend(self._check_fstring(node, content, file_path))

        return findings

    def _check_execute_call(
        self, node: ast.Call, content: str, file_path: Path
    ) -> List[Finding]:
        """Check execute() calls for injection risks."""
        findings = []

        # Check if this is a .execute() call
        if not (isinstance(node.func, ast.Attribute) and
                node.func.attr in ('execute', 'executemany', 'raw', 'execute_sql')):
            return findings

        if not node.args:
            return findings

        first_arg = node.args[0]

        # Check for f-string
        if isinstance(first_arg, ast.JoinedStr):
            findings.append(self._make_finding(
                severity=Severity.HIGH,
                message="SQL query built with f-string in execute()",
                file_path=file_path,
                line=node.lineno,
                column=node.col_offset,
                snippet=self._get_line_at(content, node.lineno),
                recommendation="Use parameterized query: execute(sql, params)",
                rule_id="fstring_execute",
            ))

        # Check for .format()
        elif isinstance(first_arg, ast.Call):
            if isinstance(first_arg.func, ast.Attribute):
                if first_arg.func.attr == 'format':
                    findings.append(self._make_finding(
                        severity=Severity.HIGH,
                        message="SQL query built with .format() in execute()",
                        file_path=file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        snippet=self._get_line_at(content, node.lineno),
                        recommendation="Use parameterized query: execute(sql, params)",
                        rule_id="format_execute",
                    ))

        # Check for string concatenation
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
            findings.append(self._make_finding(
                severity=Severity.HIGH,
                message="SQL query built with string concatenation",
                file_path=file_path,
                line=node.lineno,
                column=node.col_offset,
                snippet=self._get_line_at(content, node.lineno),
                recommendation="Use parameterized query: execute(sql, params)",
                rule_id="concat_execute",
            ))

        # Check for % formatting
        elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
            findings.append(self._make_finding(
                severity=Severity.HIGH,
                message="SQL query built with % formatting",
                file_path=file_path,
                line=node.lineno,
                column=node.col_offset,
                snippet=self._get_line_at(content, node.lineno),
                recommendation="Use parameterized query: execute(sql, params)",
                rule_id="percent_execute",
            ))

        return findings

    def _check_fstring(
        self, node: ast.JoinedStr, content: str, file_path: Path
    ) -> List[Finding]:
        """Check f-strings for SQL content."""
        findings = []

        # Reconstruct the f-string content
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant):
                parts.append(str(value.value))
            else:
                parts.append("{...}")

        fstring_content = ''.join(parts).upper()

        # Check for SQL keywords
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE']
        if any(kw in fstring_content for kw in sql_keywords):
            # Check if it has interpolation
            has_interpolation = any(
                isinstance(v, ast.FormattedValue) for v in node.values
            )

            if has_interpolation:
                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message="f-string contains SQL keywords with interpolation",
                    file_path=file_path,
                    line=node.lineno,
                    column=node.col_offset,
                    snippet=self._get_line_at(content, node.lineno),
                    recommendation="Use parameterized queries instead of f-strings for SQL",
                    rule_id="fstring_sql",
                ))

        return findings

    def _regex_detection(self, content: str, file_path: Path) -> List[Finding]:
        """Regex-based detection for edge cases."""
        findings = []

        patterns = [
            (self.FSTRING_SQL_PATTERN, "f-string SQL construction"),
            (self.FORMAT_SQL_PATTERN, ".format() SQL construction"),
            (self.CONCAT_SQL_PATTERN, "String concatenation SQL"),
        ]

        for pattern, description in patterns:
            for match in pattern.finditer(content):
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.MEDIUM,
                    message=f"Potential SQL injection: {description}",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group()[:80],
                    recommendation="Review and use parameterized queries",
                    rule_id="regex_sql_pattern",
                ))

        return findings


# ============================================================================
# PERFORMANCE VALIDATOR
# ============================================================================

class PerformanceValidator(BaseSQLValidator):
    """Analyzes queries for performance issues."""

    id = "performance"

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        findings = []

        # Check for SELECT *
        findings.extend(self._check_select_star(content, file_path))

        # Check for leading wildcards in LIKE
        findings.extend(self._check_like_patterns(content, file_path))

        # Check for missing indexes hints
        findings.extend(self._check_join_conditions(content, file_path))

        # Check for N+1 query patterns
        findings.extend(self._check_n_plus_one(content, file_path))

        # Check for DISTINCT abuse
        findings.extend(self._check_distinct_abuse(content, file_path))

        return findings

    def _check_select_star(self, content: str, file_path: Path) -> List[Finding]:
        """Check for SELECT * usage."""
        findings = []

        pattern = re.compile(r'SELECT\s+\*\s+FROM', re.IGNORECASE)
        for match in pattern.finditer(content):
            line_num = self._get_line_number(content, match.start())
            findings.append(self._make_finding(
                severity=Severity.MEDIUM,
                message="SELECT * retrieves unnecessary columns",
                file_path=file_path,
                line=line_num,
                snippet=match.group(),
                recommendation="Explicitly list required columns",
                rule_id="select_star",
                auto_fixable=True,
            ))

        return findings

    def _check_like_patterns(self, content: str, file_path: Path) -> List[Finding]:
        """Check for inefficient LIKE patterns."""
        findings = []

        # Leading wildcard prevents index usage
        pattern = re.compile(r"LIKE\s+['\"]%", re.IGNORECASE)
        for match in pattern.finditer(content):
            line_num = self._get_line_number(content, match.start())
            findings.append(self._make_finding(
                severity=Severity.MEDIUM,
                message="LIKE with leading wildcard prevents index usage",
                file_path=file_path,
                line=line_num,
                snippet=match.group(),
                recommendation="Use full-text search or remove leading %",
                rule_id="like_leading_wildcard",
            ))

        return findings

    def _check_join_conditions(self, content: str, file_path: Path) -> List[Finding]:
        """Check for JOINs without proper conditions."""
        findings = []

        # Cross join detection
        pattern = re.compile(r'FROM\s+\w+\s*,\s*\w+', re.IGNORECASE)
        for match in pattern.finditer(content):
            line_num = self._get_line_number(content, match.start())
            findings.append(self._make_finding(
                severity=Severity.MEDIUM,
                message="Implicit cross join detected (comma-separated tables)",
                file_path=file_path,
                line=line_num,
                snippet=match.group(),
                recommendation="Use explicit JOIN syntax with ON clause",
                rule_id="implicit_cross_join",
            ))

        return findings

    def _check_n_plus_one(self, content: str, file_path: Path) -> List[Finding]:
        """Check for N+1 query patterns."""
        findings = []

        # Check for SELECT inside loop patterns (in Python)
        if file_path.suffix == '.py':
            pattern = re.compile(
                r'for\s+\w+\s+in\s+.*?:\s*\n\s*.*?\.execute\(',
                re.MULTILINE | re.DOTALL
            )
            for match in pattern.finditer(content):
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message="Potential N+1 query: execute() inside loop",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group()[:80],
                    recommendation="Use batch query or JOIN to fetch all data at once",
                    rule_id="n_plus_one",
                ))

        return findings

    def _check_distinct_abuse(self, content: str, file_path: Path) -> List[Finding]:
        """Check for DISTINCT that might indicate join issues."""
        findings = []

        pattern = re.compile(r'SELECT\s+DISTINCT\s+\*', re.IGNORECASE)
        for match in pattern.finditer(content):
            line_num = self._get_line_number(content, match.start())
            findings.append(self._make_finding(
                severity=Severity.MEDIUM,
                message="SELECT DISTINCT * often indicates join issues",
                file_path=file_path,
                line=line_num,
                snippet=match.group(),
                recommendation="Review JOINs for duplicates or select specific columns",
                rule_id="distinct_star",
            ))

        return findings


# ============================================================================
# SCHEMA VALIDATOR
# ============================================================================

class SchemaValidator(BaseSQLValidator):
    """Analyzes schema definitions for issues."""

    id = "schema"

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        findings = []

        # Check CREATE TABLE statements
        findings.extend(self._check_create_table(content, file_path, config))

        # Check for reserved word usage
        findings.extend(self._check_reserved_words(content, file_path))

        # Check naming conventions
        findings.extend(self._check_naming_conventions(content, file_path))

        return findings

    def _check_create_table(
        self, content: str, file_path: Path, config: SQLAnalyzerConfig
    ) -> List[Finding]:
        """Check CREATE TABLE statements."""
        findings = []

        # Find CREATE TABLE blocks
        pattern = re.compile(
            r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.*?)\)',
            re.IGNORECASE | re.DOTALL
        )

        for match in pattern.finditer(content):
            table_name = match.group(1)
            table_def = match.group(2)
            line_num = self._get_line_number(content, match.start())

            # Check for missing primary key
            if 'PRIMARY KEY' not in table_def.upper():
                findings.append(self._make_finding(
                    severity=Severity.HIGH,
                    message=f"Table '{table_name}' has no primary key",
                    file_path=file_path,
                    line=line_num,
                    snippet=f"CREATE TABLE {table_name}",
                    recommendation="Add PRIMARY KEY column",
                    rule_id="missing_pk",
                ))

            # Check for audit columns
            for audit_col in config.required_audit_columns:
                if audit_col.lower() not in table_def.lower():
                    findings.append(self._make_finding(
                        severity=Severity.LOW,
                        message=f"Table '{table_name}' missing audit column '{audit_col}'",
                        file_path=file_path,
                        line=line_num,
                        snippet=f"CREATE TABLE {table_name}",
                        recommendation=f"Add {audit_col} TIMESTAMP column",
                        rule_id="missing_audit_column",
                    ))

            # Check for VARCHAR without length
            varchar_pattern = re.compile(r'VARCHAR\s*(?!\()', re.IGNORECASE)
            if varchar_pattern.search(table_def):
                findings.append(self._make_finding(
                    severity=Severity.MEDIUM,
                    message=f"Table '{table_name}' uses VARCHAR without length",
                    file_path=file_path,
                    line=line_num,
                    snippet="VARCHAR",
                    recommendation="Specify VARCHAR length: VARCHAR(255)",
                    rule_id="varchar_no_length",
                ))

        return findings

    def _check_reserved_words(self, content: str, file_path: Path) -> List[Finding]:
        """Check for SQL reserved words used as identifiers."""
        findings = []

        reserved_words = {
            'user', 'order', 'group', 'select', 'table', 'index',
            'key', 'primary', 'foreign', 'check', 'default', 'column'
        }

        # Check table names
        table_pattern = re.compile(r'CREATE\s+TABLE\s+(\w+)', re.IGNORECASE)
        for match in table_pattern.finditer(content):
            name = match.group(1).lower()
            if name in reserved_words:
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.MEDIUM,
                    message=f"Table name '{name}' is a SQL reserved word",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group(),
                    recommendation=f"Rename table or quote identifier: \"{name}\"",
                    rule_id="reserved_word_table",
                ))

        return findings

    def _check_naming_conventions(self, content: str, file_path: Path) -> List[Finding]:
        """Check naming conventions."""
        findings = []

        # Check for inconsistent case (mixing camelCase and snake_case)
        table_pattern = re.compile(r'CREATE\s+TABLE\s+(\w+)', re.IGNORECASE)
        for match in table_pattern.finditer(content):
            name = match.group(1)

            # Detect mixed case
            has_upper = any(c.isupper() for c in name)
            has_lower = any(c.islower() for c in name)
            has_underscore = '_' in name

            if has_upper and has_lower and has_underscore:
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=Severity.LOW,
                    message=f"Mixed naming convention: '{name}'",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group(),
                    recommendation="Use consistent snake_case or PascalCase",
                    rule_id="mixed_naming",
                ))

        return findings


# ============================================================================
# MIGRATION VALIDATOR
# ============================================================================

class MigrationValidator(BaseSQLValidator):
    """Analyzes database migrations for issues."""

    id = "migration"

    BREAKING_CHANGES = [
        (r"DROP\s+TABLE", "table_drop", Severity.HIGH),
        (r"DROP\s+COLUMN", "column_drop", Severity.HIGH),
        (r"ALTER\s+TABLE.*\s+DROP", "alter_drop", Severity.HIGH),
        (r"ALTER\s+TABLE.*\s+TYPE", "type_change", Severity.MEDIUM),
        (r"RENAME\s+COLUMN", "column_rename", Severity.MEDIUM),
        (r"RENAME\s+TABLE", "table_rename", Severity.MEDIUM),
    ]

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        findings = []

        # Check migration naming
        findings.extend(self._check_naming(file_path))

        # Check for breaking changes
        findings.extend(self._check_breaking_changes(content, file_path))

        # Check for rollback
        findings.extend(self._check_rollback(content, file_path))

        # Check for data migrations
        findings.extend(self._check_data_migration(content, file_path))

        return findings

    def _check_naming(self, file_path: Path) -> List[Finding]:
        """Check migration file naming conventions."""
        findings = []

        valid_patterns = [
            r"^\d{14}_.*\.sql$",  # Timestamp: 20250215123045_add_users.sql
            r"^V\d+__.*\.sql$",   # Flyway: V1__initial.sql
            r"^\d{4}_.*\.py$",    # Alembic: 0001_initial.py
        ]

        filename = file_path.name
        if not any(re.match(p, filename) for p in valid_patterns):
            findings.append(self._make_finding(
                severity=Severity.LOW,
                message="Migration filename doesn't follow conventions",
                file_path=file_path,
                line=0,
                recommendation="Use timestamp_description.sql format",
                rule_id="migration_naming",
            ))

        return findings

    def _check_breaking_changes(self, content: str, file_path: Path) -> List[Finding]:
        """Check for breaking schema changes."""
        findings = []

        for pattern, change_type, severity in self.BREAKING_CHANGES:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = self._get_line_number(content, match.start())
                findings.append(self._make_finding(
                    severity=severity,
                    message=f"Breaking change: {change_type}",
                    file_path=file_path,
                    line=line_num,
                    snippet=match.group(),
                    recommendation="Ensure backward compatibility or major version bump",
                    rule_id=f"breaking_{change_type}",
                ))

        return findings

    def _check_rollback(self, content: str, file_path: Path) -> List[Finding]:
        """Check for rollback/down migration."""
        findings = []

        content_lower = content.lower()
        has_rollback = any(kw in content_lower for kw in [
            'down', 'rollback', 'revert', 'downgrade'
        ])

        if not has_rollback:
            findings.append(self._make_finding(
                severity=Severity.MEDIUM,
                message="Migration missing rollback instructions",
                file_path=file_path,
                line=0,
                recommendation="Add down/rollback section for revertability",
                rule_id="missing_rollback",
            ))

        return findings

    def _check_data_migration(self, content: str, file_path: Path) -> List[Finding]:
        """Check for data migrations mixed with schema."""
        findings = []

        has_ddl = any(kw in content.upper() for kw in ['CREATE', 'ALTER', 'DROP'])
        has_dml = any(kw in content.upper() for kw in ['INSERT', 'UPDATE', 'DELETE'])

        if has_ddl and has_dml:
            findings.append(self._make_finding(
                severity=Severity.MEDIUM,
                message="Migration mixes schema changes (DDL) with data changes (DML)",
                file_path=file_path,
                line=0,
                recommendation="Separate schema and data migrations",
                rule_id="mixed_ddl_dml",
            ))

        return findings


# ============================================================================
# ORM VALIDATOR
# ============================================================================

class ORMValidator(BaseSQLValidator):
    """Analyzes ORM models for SQL issues."""

    id = "orm"

    def validate(
        self,
        content: str,
        file_path: Path,
        config: SQLAnalyzerConfig,
        context: Dict[str, Any]
    ) -> List[Finding]:
        # Only process Python files
        if file_path.suffix != '.py':
            return []

        findings = []

        try:
            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # Check for SQLAlchemy models
                    if self._is_sqlalchemy_model(node):
                        findings.extend(
                            self._check_sqlalchemy_model(node, content, file_path)
                        )

                    # Check for Django models
                    if self._is_django_model(node):
                        findings.extend(
                            self._check_django_model(node, content, file_path)
                        )

        except SyntaxError:
            pass

        return findings

    def _is_sqlalchemy_model(self, node: ast.ClassDef) -> bool:
        """Check if class is a SQLAlchemy model."""
        for item in node.body:
            if isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name) and target.id == '__tablename__':
                        return True
        return False

    def _is_django_model(self, node: ast.ClassDef) -> bool:
        """Check if class inherits from Django Model."""
        for base in node.bases:
            if isinstance(base, ast.Attribute):
                if base.attr == 'Model':
                    return True
            if isinstance(base, ast.Name):
                if base.id in ('Model', 'models.Model'):
                    return True
        return False

    def _check_sqlalchemy_model(
        self, node: ast.ClassDef, content: str, file_path: Path
    ) -> List[Finding]:
        """Check SQLAlchemy model for issues."""
        findings = []

        has_primary_key = False

        for item in node.body:
            if isinstance(item, ast.Assign):
                # Check for Column definitions
                if isinstance(item.value, ast.Call):
                    func = item.value.func
                    if isinstance(func, ast.Name) and func.id == 'Column':
                        # Check for primary key
                        for kw in item.value.keywords:
                            if kw.arg == 'primary_key':
                                if isinstance(kw.value, ast.Constant) and kw.value.value:
                                    has_primary_key = True

                        # Check for String without length
                        for arg in item.value.args:
                            if isinstance(arg, ast.Call):
                                if isinstance(arg.func, ast.Name) and arg.func.id == 'String':
                                    if not arg.args:  # No length specified
                                        target_name = item.targets[0].id if item.targets else "column"
                                        findings.append(self._make_finding(
                                            severity=Severity.MEDIUM,
                                            message=f"Column '{target_name}' uses String without length",
                                            file_path=file_path,
                                            line=item.lineno,
                                            snippet=self._get_line_at(content, item.lineno),
                                            recommendation="Add length: String(255)",
                                            rule_id="orm_string_no_length",
                                        ))

        if not has_primary_key:
            findings.append(self._make_finding(
                severity=Severity.HIGH,
                message=f"Model '{node.name}' has no primary key",
                file_path=file_path,
                line=node.lineno,
                recommendation="Add: id = Column(Integer, primary_key=True)",
                rule_id="orm_missing_pk",
            ))

        return findings

    def _check_django_model(
        self, node: ast.ClassDef, content: str, file_path: Path
    ) -> List[Finding]:
        """Check Django model for issues."""
        findings = []

        # Django auto-adds id, so check other things
        for item in node.body:
            if isinstance(item, ast.Assign):
                if isinstance(item.value, ast.Call):
                    func = item.value.func
                    if isinstance(func, ast.Attribute):
                        # Check for CharField without max_length
                        if func.attr == 'CharField':
                            has_max_length = any(
                                kw.arg == 'max_length' for kw in item.value.keywords
                            )
                            if not has_max_length:
                                target_name = item.targets[0].id if item.targets else "field"
                                findings.append(self._make_finding(
                                    severity=Severity.HIGH,
                                    message=f"CharField '{target_name}' missing max_length",
                                    file_path=file_path,
                                    line=item.lineno,
                                    snippet=self._get_line_at(content, item.lineno),
                                    recommendation="Add max_length parameter",
                                    rule_id="django_charfield_no_length",
                                ))

        return findings


# ============================================================================
# MAIN ANALYZER
# ============================================================================

class SQLEcosystemAnalyzer:
    """
    Main SQL analysis orchestrator.

    Follows the Analyzer protocol for integration with code_audit runner.
    """

    id = "sql_ecosystem"
    version = "1.0.0"

    # Registry of built-in validators
    _BUILTIN_VALIDATORS: ClassVar[Dict[str, Type[BaseSQLValidator]]] = {
        "syntax": SyntaxValidator,
        "security": SecurityValidator,
        "injection": PythonSQLInjectionValidator,
        "performance": PerformanceValidator,
        "schema": SchemaValidator,
        "migration": MigrationValidator,
        "orm": ORMValidator,
    }

    def __init__(self, config: SQLAnalyzerConfig | None = None):
        self.config = config or SQLAnalyzerConfig()
        self.validators: Dict[str, BaseSQLValidator] = {}

        # Initialize enabled validators
        for validator_id in self.config.enabled_validators:
            if validator_id in self._BUILTIN_VALIDATORS:
                self.validators[validator_id] = self._BUILTIN_VALIDATORS[validator_id]()

    @classmethod
    def from_root(cls, root: Path) -> "SQLEcosystemAnalyzer":
        """Create analyzer with auto-discovered config."""
        config = SQLAnalyzerConfig.discover(root)
        return cls(config)

    @classmethod
    def register_validator(cls, validator_class: Type[BaseSQLValidator]) -> None:
        """Register a custom validator."""
        cls._BUILTIN_VALIDATORS[validator_class.id] = validator_class

    def run(self, root: Path, files: List[Path]) -> List[Finding]:
        """
        Run SQL analysis on files.

        This is the main entry point following the Analyzer protocol.
        """
        findings = []
        context: Dict[str, Any] = {}

        for file_path in files:
            # Determine file type and run appropriate validators
            if file_path.suffix in ('.sql', '.prc', '.fnc', '.trg'):
                findings.extend(self._analyze_sql_file(file_path, context))
            elif file_path.suffix == '.py':
                findings.extend(self._analyze_python_file(file_path, context))

        # Filter by severity threshold (using numeric ordering)
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        threshold_level = severity_order.get(self.config.severity_threshold, 0)
        findings = [
            f for f in findings
            if severity_order.get(f.severity, 0) >= threshold_level
        ]

        return findings

    def _analyze_sql_file(self, file_path: Path, context: Dict[str, Any]) -> List[Finding]:
        """Analyze a SQL file."""
        findings = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            return [Finding(
                finding_id=f"sql_read_error_{file_path}",
                type=AnalyzerType.SQL,
                severity=Severity.LOW,
                confidence=1.0,
                message=f"Could not read file: {e}",
                location=Location(path=str(file_path), line_start=0, line_end=0),
                fingerprint=make_fingerprint("read_error", str(file_path), "", ""),
                snippet="",
                metadata={"rule_id": "read_error"},
            )]

        # Determine if this is a migration file
        is_migration = 'migration' in str(file_path).lower()

        # Run appropriate validators
        sql_validators = ['syntax', 'security', 'performance', 'schema']
        if is_migration:
            sql_validators.append('migration')

        for validator_id in sql_validators:
            if validator_id in self.validators:
                validator = self.validators[validator_id]
                findings.extend(validator.validate(content, file_path, self.config, context))

        return findings

    def _analyze_python_file(self, file_path: Path, context: Dict[str, Any]) -> List[Finding]:
        """Analyze a Python file for SQL issues."""
        findings = []

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return findings

        # Run Python-specific validators
        python_validators = ['injection', 'orm']

        for validator_id in python_validators:
            if validator_id in self.validators:
                validator = self.validators[validator_id]
                findings.extend(validator.validate(content, file_path, self.config, context))

        return findings

    def scan_directory(self, root: Path) -> List[Path]:
        """Scan directory for SQL-related files."""
        files = []

        all_patterns = (
            self.config.sql_patterns +
            self.config.orm_patterns +
            self.config.migration_patterns +
            self.config.python_sql_patterns
        )

        for pattern in all_patterns:
            files.extend(root.glob(pattern))

        return list(set(files))  # Deduplicate


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def analyze_sql_project(root: Path) -> List[Finding]:
    """Convenience function to analyze a SQL project."""
    analyzer = SQLEcosystemAnalyzer.from_root(root)
    files = analyzer.scan_directory(root)
    return analyzer.run(root, files)


def check_sql_injection(python_file: Path) -> List[Finding]:
    """Quick check for SQL injection in a Python file."""
    config = SQLAnalyzerConfig(enabled_validators={"injection"})
    analyzer = SQLEcosystemAnalyzer(config)
    return analyzer.run(python_file.parent, [python_file])
