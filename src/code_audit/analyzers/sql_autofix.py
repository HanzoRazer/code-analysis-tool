"""
SQL Auto-Fixer
==============
Automatically fixes common SQL and security issues detected by the SQL Ecosystem Analyzer.

Supported fixes:
- SQL injection (f-string → parameterized query)
- Shell injection (shell=True → shlex.split())
- SELECT * → explicit columns

Usage:
    from code_audit.analyzers.sql_autofix import AutoFixer, apply_fixes

    fixer = AutoFixer()
    fixes = fixer.analyze_and_fix(file_path)

    # Preview fixes
    for fix in fixes:
        print(fix.describe())

    # Apply fixes
    apply_fixes(file_path, fixes)
"""

from __future__ import annotations

import ast
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class Fix:
    """Represents a code fix that can be applied."""

    file_path: Path
    line_start: int
    line_end: int
    old_code: str
    new_code: str
    rule_id: str
    description: str
    confidence: float = 0.9  # How confident we are this fix is correct

    def describe(self) -> str:
        """Human-readable description of the fix."""
        return (
            f"[{self.rule_id}] {self.description}\n"
            f"  File: {self.file_path}:{self.line_start}\n"
            f"  - {self.old_code.strip()[:60]}...\n"
            f"  + {self.new_code.strip()[:60]}..."
        )

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "file_path": str(self.file_path),
            "line_start": self.line_start,
            "line_end": self.line_end,
            "old_code": self.old_code,
            "new_code": self.new_code,
            "rule_id": self.rule_id,
            "description": self.description,
            "confidence": self.confidence,
        }


@dataclass
class FixResult:
    """Result of applying fixes to a file."""

    file_path: Path
    fixes_applied: int
    fixes_skipped: int
    backup_path: Optional[Path] = None
    errors: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


class AutoFixer:
    """Analyzes Python files and generates fixes for SQL/security issues."""

    def __init__(self, create_backups: bool = True):
        self.create_backups = create_backups
        self._fixers: List[Callable[[Path, str], List[Fix]]] = [
            self._fix_fstring_sql_injection,
            self._fix_format_sql_injection,
            self._fix_shell_injection,
            self._fix_percent_sql_injection,
        ]

    def analyze_file(self, file_path: Path) -> List[Fix]:
        """Analyze a file and return all possible fixes."""
        if not file_path.exists():
            return []

        if file_path.suffix != '.py':
            return []

        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return []

        fixes = []
        for fixer in self._fixers:
            fixes.extend(fixer(file_path, content))

        # Sort by line number (reverse) so we can apply from bottom up
        fixes.sort(key=lambda f: f.line_start, reverse=True)

        return fixes

    def analyze_directory(self, root: Path, pattern: str = "**/*.py") -> Dict[Path, List[Fix]]:
        """Analyze all Python files in a directory."""
        results = {}
        for file_path in root.glob(pattern):
            fixes = self.analyze_file(file_path)
            if fixes:
                results[file_path] = fixes
        return results

    # =========================================================================
    # F-STRING SQL INJECTION FIXER
    # =========================================================================

    def _fix_fstring_sql_injection(self, file_path: Path, content: str) -> List[Fix]:
        """Fix f-string SQL injection patterns."""
        fixes = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return fixes

        lines = content.splitlines(keepends=True)

        for node in ast.walk(tree):
            # Look for cursor.execute(f"...") patterns
            if not isinstance(node, ast.Call):
                continue

            if not isinstance(node.func, ast.Attribute):
                continue

            if node.func.attr not in ('execute', 'executemany'):
                continue

            if not node.args:
                continue

            first_arg = node.args[0]

            # Check for f-string
            if isinstance(first_arg, ast.JoinedStr):
                fix = self._create_fstring_fix(node, first_arg, lines, file_path)
                if fix:
                    fixes.append(fix)

        return fixes

    def _create_fstring_fix(
        self,
        call_node: ast.Call,
        fstring_node: ast.JoinedStr,
        lines: List[str],
        file_path: Path
    ) -> Optional[Fix]:
        """Create a fix for an f-string SQL injection."""
        # Extract the f-string components
        sql_parts = []
        params = []
        param_names = []

        for i, value in enumerate(fstring_node.values):
            if isinstance(value, ast.Constant):
                sql_parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                # Extract variable name
                param_name = self._extract_var_name(value.value)
                if param_name:
                    placeholder = f":{param_name}"
                    sql_parts.append(placeholder)
                    param_names.append(param_name)
                else:
                    # Can't safely fix - unknown expression
                    return None

        if not param_names:
            return None  # No interpolation, not an injection risk

        # Build the fixed code
        sql_string = ''.join(sql_parts)
        params_dict = '{' + ', '.join(f'"{p}": {p}' for p in param_names) + '}'

        # Get the original line(s)
        start_line = call_node.lineno
        end_line = getattr(call_node, 'end_lineno', start_line)

        old_code = ''.join(lines[start_line - 1:end_line])

        # Build new code - get the object being called on
        obj_name = self._extract_var_name(call_node.func.value) or "cursor"
        method_name = call_node.func.attr

        # Preserve indentation
        indent = len(old_code) - len(old_code.lstrip())
        indent_str = ' ' * indent

        new_code = f'{indent_str}{obj_name}.{method_name}("{sql_string}", {params_dict})\n'

        return Fix(
            file_path=file_path,
            line_start=start_line,
            line_end=end_line,
            old_code=old_code,
            new_code=new_code,
            rule_id="fstring_sql_injection",
            description="Convert f-string SQL to parameterized query",
            confidence=0.85,
        )

    def _extract_var_name(self, node: ast.AST) -> Optional[str]:
        """Extract variable name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._extract_var_name(node.value)
            if base:
                return f"{base}_{node.attr}"
            return node.attr
        elif isinstance(node, ast.Subscript):
            base = self._extract_var_name(node.value)
            if isinstance(node.slice, ast.Constant):
                return f"{base}_{node.slice.value}"
            return base
        return None

    # =========================================================================
    # .format() SQL INJECTION FIXER
    # =========================================================================

    def _fix_format_sql_injection(self, file_path: Path, content: str) -> List[Fix]:
        """Fix .format() SQL injection patterns."""
        fixes = []

        # Pattern: "SELECT ... {}".format(var) - must contain {} placeholder
        pattern = re.compile(
            r'(["\'])([^\n]*?(?:SELECT|INSERT|UPDATE|DELETE)[^\n]*?\{\}[^\n]*?)\1\.format\s*\(([^)]+)\)',
            re.IGNORECASE
        )

        lines = content.splitlines(keepends=True)

        for match in pattern.finditer(content):
            line_num = content[:match.start()].count('\n') + 1

            quote = match.group(1)
            sql_template = match.group(2)
            format_args = match.group(3).strip()

            # Convert {} placeholders to :param style
            param_count = sql_template.count('{}')
            if param_count == 0:
                continue

            # Parse format arguments
            arg_names = [a.strip() for a in format_args.split(',')]

            if len(arg_names) != param_count:
                continue  # Can't safely fix

            # Replace {} with :param_name
            new_sql = sql_template
            for i, arg in enumerate(arg_names):
                new_sql = new_sql.replace('{}', f':{arg}', 1)

            params_dict = '{' + ', '.join(f'"{a}": {a}' for a in arg_names) + '}'

            old_code = match.group(0)
            new_code = f'{quote}{new_sql}{quote}, {params_dict}'

            fixes.append(Fix(
                file_path=file_path,
                line_start=line_num,
                line_end=line_num,
                old_code=old_code,
                new_code=new_code,
                rule_id="format_sql_injection",
                description="Convert .format() SQL to parameterized query",
                confidence=0.8,
            ))

        return fixes

    # =========================================================================
    # % FORMATTING SQL INJECTION FIXER
    # =========================================================================

    def _fix_percent_sql_injection(self, file_path: Path, content: str) -> List[Fix]:
        """Fix % formatting SQL injection patterns."""
        fixes = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return fixes

        lines = content.splitlines(keepends=True)

        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp):
                continue

            if not isinstance(node.op, ast.Mod):
                continue

            # Check if left side is a SQL string
            if not isinstance(node.left, ast.Constant):
                continue

            sql_string = str(node.left.value)
            sql_upper = sql_string.upper()

            if not any(kw in sql_upper for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                continue

            # Count %s placeholders
            placeholder_count = sql_string.count('%s')
            if placeholder_count == 0:
                continue

            # Get the right side (tuple or single value)
            if isinstance(node.right, ast.Tuple):
                args = [self._extract_var_name(e) for e in node.right.elts]
            else:
                args = [self._extract_var_name(node.right)]

            if None in args or len(args) != placeholder_count:
                continue  # Can't safely fix

            # Replace %s with :param
            new_sql = sql_string
            for arg in args:
                new_sql = new_sql.replace('%s', f':{arg}', 1)

            params_dict = '{' + ', '.join(f'"{a}": {a}' for a in args) + '}'

            line_num = node.lineno
            old_code = ''.join(lines[line_num - 1:node.end_lineno])

            indent = len(old_code) - len(old_code.lstrip())
            new_code = ' ' * indent + f'"{new_sql}", {params_dict}\n'

            fixes.append(Fix(
                file_path=file_path,
                line_start=line_num,
                line_end=node.end_lineno,
                old_code=old_code,
                new_code=new_code,
                rule_id="percent_sql_injection",
                description="Convert % formatting SQL to parameterized query",
                confidence=0.75,
            ))

        return fixes

    # =========================================================================
    # SHELL INJECTION FIXER
    # =========================================================================

    def _fix_shell_injection(self, file_path: Path, content: str) -> List[Fix]:
        """Fix shell=True injection patterns."""
        fixes = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return fixes

        lines = content.splitlines(keepends=True)
        needs_shlex_import = 'import shlex' not in content and 'from shlex' not in content

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Check for subprocess.run or subprocess.Popen
            func = node.func
            is_subprocess_call = False

            if isinstance(func, ast.Attribute):
                if func.attr in ('run', 'Popen', 'call', 'check_call', 'check_output'):
                    is_subprocess_call = True
            elif isinstance(func, ast.Name):
                if func.id in ('run', 'Popen', 'call', 'check_call', 'check_output'):
                    is_subprocess_call = True

            if not is_subprocess_call:
                continue

            # Check for shell=True
            shell_kwarg = None
            shell_idx = None
            for i, kw in enumerate(node.keywords):
                if kw.arg == 'shell':
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        shell_kwarg = kw
                        shell_idx = i
                        break
                    elif isinstance(kw.value, ast.NameConstant) and kw.value.value is True:
                        shell_kwarg = kw
                        shell_idx = i
                        break

            if shell_kwarg is None:
                continue

            # Get the command argument (first positional arg)
            if not node.args:
                continue

            cmd_arg = node.args[0]
            cmd_name = self._extract_var_name(cmd_arg)

            if cmd_name is None:
                # Try to get string value
                if isinstance(cmd_arg, ast.Constant):
                    cmd_name = repr(cmd_arg.value)
                else:
                    continue

            line_num = node.lineno
            end_line = getattr(node, 'end_lineno', line_num)
            old_code = ''.join(lines[line_num - 1:end_line])

            # Build the fix - wrap command in shlex.split() and remove shell=True
            # Preserve any prefix before the call (e.g., "result = ")
            first_line = lines[line_num - 1]
            col_offset = getattr(node, 'col_offset', 0)
            prefix = first_line[:col_offset]  # Everything before the call (indent + assignment)

            # Reconstruct the call
            func_name = ast.unparse(node.func) if hasattr(ast, 'unparse') else 'subprocess.run'

            # New args: shlex.split(cmd) instead of cmd
            new_first_arg = f"shlex.split({cmd_name})"

            # Remove shell=True from keywords
            new_keywords = []
            for kw in node.keywords:
                if kw.arg != 'shell':
                    kw_str = f"{kw.arg}={ast.unparse(kw.value)}" if hasattr(ast, 'unparse') else f"{kw.arg}=..."
                    new_keywords.append(kw_str)

            # Other positional args
            other_args = []
            for arg in node.args[1:]:
                if hasattr(ast, 'unparse'):
                    other_args.append(ast.unparse(arg))

            all_args = [new_first_arg] + other_args + new_keywords
            new_call = f"{func_name}({', '.join(all_args)})"

            new_code = prefix + new_call + '\n'

            fix = Fix(
                file_path=file_path,
                line_start=line_num,
                line_end=end_line,
                old_code=old_code,
                new_code=new_code,
                rule_id="shell_injection",
                description="Replace shell=True with shlex.split()",
                confidence=0.9,
            )

            # Add note about import if needed
            if needs_shlex_import:
                fix.description += " (add 'import shlex' at top)"

            fixes.append(fix)

        return fixes


def apply_fixes(
    file_path: Path,
    fixes: List[Fix],
    create_backup: bool = True,
    dry_run: bool = False
) -> FixResult:
    """
    Apply fixes to a file.

    Args:
        file_path: Path to the file to fix
        fixes: List of fixes to apply (should be sorted by line_start descending)
        create_backup: Whether to create a .bak backup
        dry_run: If True, don't actually modify the file

    Returns:
        FixResult with details about what was applied
    """
    result = FixResult(file_path=file_path, fixes_applied=0, fixes_skipped=0)

    if not file_path.exists():
        result.errors.append(f"File not found: {file_path}")
        return result

    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.splitlines(keepends=True)
    except Exception as e:
        result.errors.append(f"Error reading file: {e}")
        return result

    # Check if we need to add shlex import
    needs_shlex = any(f.rule_id == 'shell_injection' for f in fixes)
    has_shlex = 'import shlex' in content or 'from shlex' in content

    # Apply fixes from bottom to top (to preserve line numbers)
    fixes_sorted = sorted(fixes, key=lambda f: f.line_start, reverse=True)

    for fix in fixes_sorted:
        try:
            # Verify the old code matches
            actual_old = ''.join(lines[fix.line_start - 1:fix.line_end])

            if actual_old.strip() != fix.old_code.strip():
                result.fixes_skipped += 1
                continue

            # Apply the fix
            lines[fix.line_start - 1:fix.line_end] = [fix.new_code]
            result.fixes_applied += 1

        except Exception as e:
            result.errors.append(f"Error applying fix at line {fix.line_start}: {e}")
            result.fixes_skipped += 1

    # Add shlex import if needed
    if needs_shlex and not has_shlex and result.fixes_applied > 0:
        # Find import section and add shlex
        for i, line in enumerate(lines):
            if line.startswith('import subprocess'):
                lines.insert(i + 1, 'import shlex\n')
                break
            elif line.startswith('import ') or line.startswith('from '):
                continue
            elif line.strip() and not line.startswith('#'):
                # Past imports, add at current position
                lines.insert(i, 'import shlex\n')
                break

    if dry_run:
        return result

    # Create backup
    if create_backup:
        backup_path = file_path.with_suffix(file_path.suffix + '.bak')
        try:
            shutil.copy2(file_path, backup_path)
            result.backup_path = backup_path
        except Exception as e:
            result.errors.append(f"Error creating backup: {e}")

    # Write the fixed content
    try:
        file_path.write_text(''.join(lines), encoding='utf-8')
    except Exception as e:
        result.errors.append(f"Error writing file: {e}")

    return result


def fix_file(file_path: Path, dry_run: bool = False) -> FixResult:
    """Convenience function to analyze and fix a single file."""
    fixer = AutoFixer()
    fixes = fixer.analyze_file(file_path)

    if not fixes:
        return FixResult(file_path=file_path, fixes_applied=0, fixes_skipped=0)

    return apply_fixes(file_path, fixes, dry_run=dry_run)


def fix_directory(root: Path, pattern: str = "**/*.py", dry_run: bool = False) -> Dict[Path, FixResult]:
    """Fix all Python files in a directory."""
    fixer = AutoFixer()
    all_fixes = fixer.analyze_directory(root, pattern)

    results = {}
    for file_path, fixes in all_fixes.items():
        results[file_path] = apply_fixes(file_path, fixes, dry_run=dry_run)

    return results
