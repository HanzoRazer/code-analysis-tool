"""Security analyzer — detects common security vulnerabilities.

v1 scope: high confidence, low false positives, single-file analysis.
Focus on obvious anti-patterns that are almost always problematic.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Optional

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint
from code_audit.rules import (
    SEC_HARDCODED_SECRET_001,
    SEC_EVAL_001,
    SEC_SUBPROCESS_SHELL_001,
    SEC_SQL_INJECTION_001,
    SEC_PICKLE_LOAD_001,
    SEC_YAML_UNSAFE_001,
)


# ── Secret detection patterns ───────────────────────────────────────────

# Common secret variable names (case-insensitive)
_SECRET_VAR_PATTERNS = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|api_secret|"
    r"auth_token|access_token|private_key|encryption_key|"
    r"client_secret|jwt_secret|session_secret|db_password|"
    r"database_password|mysql_password|postgres_password|"
    r"redis_password|aws_secret|stripe_secret|twilio_auth)",
    re.IGNORECASE,
)

# Patterns that look like actual secrets (not placeholders)
_SECRET_VALUE_PATTERNS = [
    # AWS keys (AKIA...)
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
    # Generic API key patterns (long alphanumeric)
    re.compile(r"^[a-zA-Z0-9_\-]{20,}$"),
    # JWT tokens
    re.compile(r"^eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$"),
]

# Placeholder values to ignore
_PLACEHOLDER_PATTERNS = [
    re.compile(r"^(your[_-]?|my[_-]?|example[_-]?|test[_-]?|dummy[_-]?|fake[_-]?)", re.I),
    re.compile(r"(xxx+|placeholder|changeme|fixme|todo)", re.I),
    re.compile(r"^\$\{.*\}$"),  # ${VAR} templates
    re.compile(r"^%\(.*\)s$"),  # %(var)s templates
    re.compile(r"^\{.*\}$"),    # {var} templates
]


def _is_secret_var_name(name: str) -> bool:
    """Check if variable name suggests it holds a secret."""
    return bool(_SECRET_VAR_PATTERNS.search(name))


def _looks_like_real_secret(value: str) -> bool:
    """Check if value looks like an actual secret (not a placeholder).

    For variables named like secrets, we're permissive: any non-empty,
    non-placeholder string is suspicious.
    """
    if not value or len(value) < 4:
        return False

    # Skip obvious placeholders
    for pattern in _PLACEHOLDER_PATTERNS:
        if pattern.search(value):
            return False

    # Check if it matches known secret patterns (high confidence)
    for pattern in _SECRET_VALUE_PATTERNS:
        if pattern.match(value):
            return True

    # For secret-named variables, any non-trivial value is suspicious
    # (The variable name filter already narrowed this down)
    if len(value) >= 6 and not value.startswith(("/", "http", "file:")):
        # Has some complexity (not just "test" or "demo")
        has_letter = any(c.isalpha() for c in value)
        has_digit_or_symbol = any(c.isdigit() or c in "_-!@#$%^&*" for c in value)
        if has_letter and has_digit_or_symbol:
            return True
        # Or it's a longer string that looks like a credential
        if len(value) >= 8:
            return True

    return False


def _build_parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    """Build a child-id → parent mapping in a single O(N) walk."""
    parent_map: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node
    return parent_map


def _get_enclosing_function(parent_map: dict[int, ast.AST], target: ast.AST) -> str:
    """Find the enclosing function name for *target* using a pre-built parent map.

    Walks up the parent chain in O(depth) instead of O(N²).
    """
    node = target
    while True:
        parent = parent_map.get(id(node))
        if parent is None:
            return "<module>"
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return parent.name
        node = parent


def _get_string_value(node: ast.expr) -> Optional[str]:
    """Extract string value from AST node if it's a constant string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_dangerous_call(node: ast.Call, func_name: str, module_name: Optional[str] = None) -> bool:
    """Check if this is a call to a specific dangerous function."""
    func = node.func

    # Direct call: eval(...)
    if isinstance(func, ast.Name) and func.id == func_name:
        return module_name is None

    # Module call: pickle.load(...)
    if isinstance(func, ast.Attribute) and func.attr == func_name:
        if module_name is None:
            return True
        if isinstance(func.value, ast.Name) and func.value.id == module_name:
            return True

    return False


# ── Analyzer class ──────────────────────────────────────────────────────


class SecurityAnalyzer:
    """Finds common security vulnerabilities.

    Rules:
      SEC_HARDCODED_SECRET_001: Hardcoded secrets in source code
      SEC_EVAL_001: Use of eval() or exec()
      SEC_SUBPROCESS_SHELL_001: subprocess with shell=True
      SEC_SQL_INJECTION_001: SQL string concatenation/formatting
      SEC_PICKLE_LOAD_001: pickle.load() (arbitrary code execution)
      SEC_YAML_UNSAFE_001: yaml.load() without safe Loader
    """

    id: str = "security"
    version: str = "1.1.0"

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        findings: list[Finding] = []

        for path in files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(source, filename=str(path))
            except SyntaxError:
                continue

            rel = path.relative_to(root).as_posix()
            parent_map = _build_parent_map(tree)

            # Run all detectors
            findings.extend(self._detect_hardcoded_secrets(tree, rel, source, parent_map))
            findings.extend(self._detect_eval_exec(tree, rel, source, parent_map))
            findings.extend(self._detect_subprocess_shell(tree, rel, source, parent_map))
            findings.extend(self._detect_sql_injection(tree, rel, source, parent_map))
            findings.extend(self._detect_pickle_load(tree, rel, source, parent_map))
            findings.extend(self._detect_yaml_unsafe(tree, rel, source, parent_map))

        # Assign stable finding IDs (fingerprint-based)
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"sec_{f.fingerprint[7:15]}_{i:04d}")

        return findings

    def _detect_hardcoded_secrets(
        self, tree: ast.AST, rel: str, source: str, parent_map: dict[int, ast.AST]
    ) -> list[Finding]:
        """Detect hardcoded secrets in assignments."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                # Check each target
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if _is_secret_var_name(var_name):
                            value = _get_string_value(node.value)
                            if value and _looks_like_real_secret(value):
                                findings.append(self._make_secret_finding(
                                    node, rel, parent_map, var_name, value
                                ))

            elif isinstance(node, ast.AnnAssign) and node.value:
                if isinstance(node.target, ast.Name):
                    var_name = node.target.id
                    if _is_secret_var_name(var_name):
                        value = _get_string_value(node.value)
                        if value and _looks_like_real_secret(value):
                            findings.append(self._make_secret_finding(
                                node, rel, parent_map, var_name, value
                            ))

        return findings

    def _make_secret_finding(
        self, node: ast.stmt, rel: str, parent_map: dict[int, ast.AST], var_name: str, value: str
    ) -> Finding:
        """Create a finding for a hardcoded secret."""
        line_start = node.lineno
        line_end = getattr(node, "end_lineno", line_start) or line_start
        symbol = _get_enclosing_function(parent_map, node)

        # Redact the actual value in snippet
        redacted = value[:4] + "..." + value[-4:] if len(value) > 12 else "***"
        snippet = f'{var_name} = "{redacted}"'

        return Finding(
            finding_id="",
            type=AnalyzerType.SECURITY,
            severity=Severity.CRITICAL,
            confidence=0.85,
            message=f"Hardcoded secret in variable '{var_name}' — use environment variables",
            location=Location(path=rel, line_start=line_start, line_end=line_end),
            fingerprint=make_fingerprint(SEC_HARDCODED_SECRET_001, rel, symbol, var_name),
            snippet=snippet,
            metadata={
                "rule_id": SEC_HARDCODED_SECRET_001,
                "variable_name": var_name,
                "context": symbol,
            },
        )

    def _detect_eval_exec(
        self, tree: ast.AST, rel: str, source: str, parent_map: dict[int, ast.AST]
    ) -> list[Finding]:
        """Detect use of eval() or exec()."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            func_name = None

            if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                func_name = func.id

            if func_name:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(parent_map, node)

                snippet = f"{func_name}(...)"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    message=f"'{func_name}()' can execute arbitrary code — avoid if possible",
                    location=Location(path=rel, line_start=line_start, line_end=line_end),
                    fingerprint=make_fingerprint(SEC_EVAL_001, rel, symbol, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": SEC_EVAL_001,
                        "function": func_name,
                        "context": symbol,
                    },
                ))

        return findings

    def _detect_subprocess_shell(
        self, tree: ast.AST, rel: str, source: str, parent_map: dict[int, ast.AST]
    ) -> list[Finding]:
        """Detect subprocess calls with shell=True and os.system()."""
        findings: list[Finding] = []

        # subprocess functions that accept shell parameter
        subprocess_funcs = {"run", "call", "check_call", "check_output", "Popen"}

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            is_subprocess_call = False
            is_os_system = False
            func_name = ""

            # subprocess.run(...) or subprocess.Popen(...)
            if isinstance(func, ast.Attribute) and func.attr in subprocess_funcs:
                if isinstance(func.value, ast.Name) and func.value.id == "subprocess":
                    is_subprocess_call = True
                    func_name = f"subprocess.{func.attr}"

            # os.system(...) — inherently uses shell
            if isinstance(func, ast.Attribute) and func.attr == "system":
                if isinstance(func.value, ast.Name) and func.value.id == "os":
                    is_os_system = True
                    func_name = "os.system"

            # os.system always flags
            if is_os_system:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(parent_map, node)

                snippet = f"{func_name}(...)"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    message=f"'{func_name}' executes commands through the shell — vulnerable to injection",
                    location=Location(path=rel, line_start=line_start, line_end=line_end),
                    fingerprint=make_fingerprint(SEC_SUBPROCESS_SHELL_001, rel, symbol, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": SEC_SUBPROCESS_SHELL_001,
                        "function": func_name,
                        "context": symbol,
                    },
                ))
                continue

            if not is_subprocess_call:
                continue

            # Check for shell=True in keywords
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        has_shell_true = True
                        break

            if has_shell_true:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(parent_map, node)

                snippet = f"{func_name}(..., shell=True)"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    message=f"'{func_name}' with shell=True is vulnerable to command injection",
                    location=Location(path=rel, line_start=line_start, line_end=line_end),
                    fingerprint=make_fingerprint(SEC_SUBPROCESS_SHELL_001, rel, symbol, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": SEC_SUBPROCESS_SHELL_001,
                        "function": func_name,
                        "context": symbol,
                    },
                ))

        return findings

    def _detect_sql_injection(
        self, tree: ast.AST, rel: str, source: str, parent_map: dict[int, ast.AST]
    ) -> list[Finding]:
        """Detect SQL injection via string formatting."""
        findings: list[Finding] = []

        # SQL keywords that suggest a query
        sql_pattern = re.compile(
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b",
            re.IGNORECASE
        )

        for node in ast.walk(tree):
            is_sql_injection = False
            snippet = ""

            # Pattern 1: f"SELECT ... {var}"
            if isinstance(node, ast.JoinedStr):
                # Reconstruct f-string to check for SQL
                parts = []
                has_variable = False
                for val in node.values:
                    if isinstance(val, ast.Constant):
                        parts.append(str(val.value))
                    elif isinstance(val, ast.FormattedValue):
                        parts.append("{...}")
                        has_variable = True

                full_str = "".join(parts)
                if has_variable and sql_pattern.search(full_str):
                    is_sql_injection = True
                    snippet = f'f"{full_str[:50]}..."' if len(full_str) > 50 else f'f"{full_str}"'

            # Pattern 2: "SELECT ... %s" % var or "SELECT ...".format(var)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                    if sql_pattern.search(node.left.value):
                        is_sql_injection = True
                        val = node.left.value
                        snippet = f'"{val[:40]}..." % ...' if len(val) > 40 else f'"{val}" % ...'

            # Pattern 3: "SELECT ...".format(...)
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == "format":
                    if isinstance(func.value, ast.Constant) and isinstance(func.value.value, str):
                        if sql_pattern.search(func.value.value):
                            is_sql_injection = True
                            val = func.value.value
                            snippet = f'"{val[:40]}...".format(...)' if len(val) > 40 else f'"{val}".format(...)'

            # Pattern 4: "SELECT ..." + var (string concatenation)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left_str = _get_string_value(node.left) if isinstance(node.left, ast.Constant) else None
                if left_str and sql_pattern.search(left_str):
                    is_sql_injection = True
                    snippet = f'"{left_str[:40]}..." + ...' if len(left_str) > 40 else f'"{left_str}" + ...'

            if is_sql_injection:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(parent_map, node)

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.CRITICAL,
                    confidence=0.80,
                    message="SQL query built with string formatting — use parameterized queries",
                    location=Location(path=rel, line_start=line_start, line_end=line_end),
                    fingerprint=make_fingerprint(SEC_SQL_INJECTION_001, rel, symbol, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": SEC_SQL_INJECTION_001,
                        "context": symbol,
                    },
                ))

        return findings

    def _detect_pickle_load(
        self, tree: ast.AST, rel: str, source: str, parent_map: dict[int, ast.AST]
    ) -> list[Finding]:
        """Detect pickle.load() which can execute arbitrary code."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            is_pickle_load = False
            func_name = ""

            # pickle.load(...) or pickle.loads(...)
            if isinstance(func, ast.Attribute) and func.attr in ("load", "loads"):
                if isinstance(func.value, ast.Name) and func.value.id == "pickle":
                    is_pickle_load = True
                    func_name = f"pickle.{func.attr}"

            if is_pickle_load:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(parent_map, node)

                snippet = f"{func_name}(...)"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    message=f"'{func_name}' can execute arbitrary code — ensure data is trusted",
                    location=Location(path=rel, line_start=line_start, line_end=line_end),
                    fingerprint=make_fingerprint(SEC_PICKLE_LOAD_001, rel, symbol, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": SEC_PICKLE_LOAD_001,
                        "function": func_name,
                        "context": symbol,
                    },
                ))

        return findings

    def _detect_yaml_unsafe(
        self, tree: ast.AST, rel: str, source: str, parent_map: dict[int, ast.AST]
    ) -> list[Finding]:
        """Detect yaml.load() without safe Loader and yaml.unsafe_load()."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func = node.func
            is_yaml_load = False
            is_unsafe_load = False

            # yaml.load(...)
            if isinstance(func, ast.Attribute) and func.attr == "load":
                if isinstance(func.value, ast.Name) and func.value.id == "yaml":
                    is_yaml_load = True

            # yaml.unsafe_load(...) — explicitly dangerous
            if isinstance(func, ast.Attribute) and func.attr == "unsafe_load":
                if isinstance(func.value, ast.Name) and func.value.id == "yaml":
                    is_unsafe_load = True

            # yaml.unsafe_load always flags
            if is_unsafe_load:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(parent_map, node)

                snippet = "yaml.unsafe_load(...)"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.HIGH,
                    confidence=0.95,
                    message="'yaml.unsafe_load()' can execute arbitrary code — use yaml.safe_load()",
                    location=Location(path=rel, line_start=line_start, line_end=line_end),
                    fingerprint=make_fingerprint(SEC_YAML_UNSAFE_001, rel, symbol, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": SEC_YAML_UNSAFE_001,
                        "function": "yaml.unsafe_load",
                        "context": symbol,
                    },
                ))
                continue

            if not is_yaml_load:
                continue

            # Check for Loader argument
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    # Check if it's SafeLoader or FullLoader
                    if isinstance(kw.value, ast.Attribute):
                        if kw.value.attr in ("SafeLoader", "FullLoader", "BaseLoader"):
                            has_safe_loader = True
                    elif isinstance(kw.value, ast.Name):
                        if kw.value.id in ("SafeLoader", "FullLoader", "BaseLoader"):
                            has_safe_loader = True
                    break

            # Also check positional args (2nd arg is Loader)
            if len(node.args) >= 2:
                loader_arg = node.args[1]
                if isinstance(loader_arg, ast.Attribute):
                    if loader_arg.attr in ("SafeLoader", "FullLoader", "BaseLoader"):
                        has_safe_loader = True
                elif isinstance(loader_arg, ast.Name):
                    if loader_arg.id in ("SafeLoader", "FullLoader", "BaseLoader"):
                        has_safe_loader = True

            if not has_safe_loader:
                line_start = node.lineno
                line_end = getattr(node, "end_lineno", line_start) or line_start
                symbol = _get_enclosing_function(parent_map, node)

                snippet = "yaml.load(...) # missing Loader"

                findings.append(Finding(
                    finding_id="",
                    type=AnalyzerType.SECURITY,
                    severity=Severity.HIGH,
                    confidence=0.90,
                    message="'yaml.load()' without Loader can execute arbitrary code — use yaml.safe_load() or Loader=SafeLoader",
                    location=Location(path=rel, line_start=line_start, line_end=line_end),
                    fingerprint=make_fingerprint(SEC_YAML_UNSAFE_001, rel, symbol, snippet),
                    snippet=snippet,
                    metadata={
                        "rule_id": SEC_YAML_UNSAFE_001,
                        "function": "yaml.load",
                        "context": symbol,
                    },
                ))

        return findings
