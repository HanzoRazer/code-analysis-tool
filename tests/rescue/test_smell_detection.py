"""
RESCUE TIER: Smell Detection Tests
===================================
Run these on ANY codebase. They PASS by detecting problems.
Green = problem found = you know what to fix.

Usage:
    pytest tests/rescue/test_smell_detection.py -v
    pytest tests/rescue/test_smell_detection.py -v --tb=no  # Clean output
"""
import pytest
from pathlib import Path
from typing import List, Dict, Any
import ast
import sys


# ============================================================================
# CONFIGURATION - Adjust these thresholds for your rescue mission
# ============================================================================

class RescueConfig:
    """Thresholds for code smell detection"""

    # God Class: Classes with too many methods/lines
    GOD_CLASS_MIN_METHODS = 15
    GOD_CLASS_MIN_LINES = 300

    # God Function: Functions that are too long
    GOD_FUNCTION_MIN_LINES = 50

    # Deep Nesting: Too many indentation levels
    MAX_NESTING_DEPTH = 4

    # Long Parameter List: Functions with too many params
    MAX_PARAMETERS = 5

    # Large File: Files that should be split
    LARGE_FILE_LINES = 500

    # Duplicate threshold (Jaccard similarity)
    DUPLICATE_THRESHOLD = 0.8


# ============================================================================
# HELPER FUNCTIONS - These do the actual detection
# ============================================================================

def find_python_files(root: Path) -> List[Path]:
    """Find all Python files in directory, excluding venv/tests"""
    exclude_dirs = {'.venv', 'venv', '__pycache__', '.git', 'node_modules', 'tests'}
    files = []

    for py_file in root.rglob('*.py'):
        if not any(excluded in py_file.parts for excluded in exclude_dirs):
            files.append(py_file)

    return sorted(files)


def parse_file_safe(file_path: Path) -> ast.Module | None:
    """Parse Python file, return None if syntax error"""
    try:
        return ast.parse(file_path.read_text(encoding='utf-8', errors='ignore'))
    except SyntaxError:
        return None


def count_lines(node: ast.AST) -> int:
    """Count lines in an AST node"""
    if hasattr(node, 'end_lineno') and hasattr(node, 'lineno'):
        return node.end_lineno - node.lineno + 1
    return 0


def get_nesting_depth(node: ast.AST, current_depth: int = 0) -> int:
    """Calculate maximum nesting depth"""
    max_depth = current_depth

    nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try,
                     ast.ExceptHandler, ast.FunctionDef, ast.AsyncFunctionDef)

    for child in ast.iter_child_nodes(node):
        if isinstance(child, nesting_nodes):
            child_depth = get_nesting_depth(child, current_depth + 1)
            max_depth = max(max_depth, child_depth)
        else:
            child_depth = get_nesting_depth(child, current_depth)
            max_depth = max(max_depth, child_depth)

    return max_depth


# ============================================================================
# SMELL DETECTORS - Each returns a list of findings
# ============================================================================

def detect_god_classes(root: Path) -> List[Dict[str, Any]]:
    """Find classes that do too much"""
    findings = []

    for py_file in find_python_files(root):
        tree = parse_file_safe(py_file)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                lines = count_lines(node)

                if len(methods) >= RescueConfig.GOD_CLASS_MIN_METHODS or lines >= RescueConfig.GOD_CLASS_MIN_LINES:
                    findings.append({
                        'type': 'god_class',
                        'file': str(py_file.relative_to(root)),
                        'line': node.lineno,
                        'name': node.name,
                        'methods': len(methods),
                        'lines': lines,
                        'severity': 'HIGH' if lines > 500 else 'MEDIUM',
                        'fix_hint': f"Split into smaller classes. Consider: {node.name}Base, {node.name}Helper"
                    })

    return findings


def detect_god_functions(root: Path) -> List[Dict[str, Any]]:
    """Find functions that are too long"""
    findings = []

    for py_file in find_python_files(root):
        tree = parse_file_safe(py_file)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lines = count_lines(node)

                if lines >= RescueConfig.GOD_FUNCTION_MIN_LINES:
                    findings.append({
                        'type': 'god_function',
                        'file': str(py_file.relative_to(root)),
                        'line': node.lineno,
                        'name': node.name,
                        'lines': lines,
                        'severity': 'HIGH' if lines > 100 else 'MEDIUM',
                        'fix_hint': "Extract helper functions. Look for logical blocks separated by comments."
                    })

    return findings


def detect_deep_nesting(root: Path) -> List[Dict[str, Any]]:
    """Find deeply nested code blocks"""
    findings = []

    for py_file in find_python_files(root):
        tree = parse_file_safe(py_file)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                depth = get_nesting_depth(node)

                if depth > RescueConfig.MAX_NESTING_DEPTH:
                    findings.append({
                        'type': 'deep_nesting',
                        'file': str(py_file.relative_to(root)),
                        'line': node.lineno,
                        'name': node.name,
                        'depth': depth,
                        'severity': 'HIGH' if depth > 6 else 'MEDIUM',
                        'fix_hint': "Use early returns, extract conditions to functions, or use guard clauses."
                    })

    return findings


def detect_long_parameter_lists(root: Path) -> List[Dict[str, Any]]:
    """Find functions with too many parameters"""
    findings = []

    for py_file in find_python_files(root):
        tree = parse_file_safe(py_file)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Count parameters (excluding self/cls)
                params = node.args.args + node.args.posonlyargs + node.args.kwonlyargs
                param_names = [p.arg for p in params if p.arg not in ('self', 'cls')]

                if len(param_names) > RescueConfig.MAX_PARAMETERS:
                    findings.append({
                        'type': 'long_parameter_list',
                        'file': str(py_file.relative_to(root)),
                        'line': node.lineno,
                        'name': node.name,
                        'param_count': len(param_names),
                        'params': param_names[:10],  # First 10
                        'severity': 'MEDIUM',
                        'fix_hint': "Create a dataclass or TypedDict to group related parameters."
                    })

    return findings


def detect_large_files(root: Path) -> List[Dict[str, Any]]:
    """Find files that should be split"""
    findings = []

    for py_file in find_python_files(root):
        try:
            content = py_file.read_text(encoding='utf-8', errors='ignore')
            lines = len(content.splitlines())

            if lines >= RescueConfig.LARGE_FILE_LINES:
                findings.append({
                    'type': 'large_file',
                    'file': str(py_file.relative_to(root)),
                    'lines': lines,
                    'severity': 'HIGH' if lines > 1000 else 'MEDIUM',
                    'fix_hint': f"Split into modules: {py_file.stem}_core.py, {py_file.stem}_helpers.py"
                })
        except Exception:
            continue

    return findings


def detect_bare_excepts(root: Path) -> List[Dict[str, Any]]:
    """Find bare except clauses (except:) that hide bugs"""
    findings = []

    for py_file in find_python_files(root):
        tree = parse_file_safe(py_file)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:  # bare except:
                    findings.append({
                        'type': 'bare_except',
                        'file': str(py_file.relative_to(root)),
                        'line': node.lineno,
                        'severity': 'HIGH',
                        'fix_hint': "Use 'except Exception:' or specific exception types."
                    })

    return findings


def detect_mutable_defaults(root: Path) -> List[Dict[str, Any]]:
    """Find mutable default arguments (common bug source)"""
    findings = []
    mutable_types = {'List', 'Dict', 'Set', 'list', 'dict', 'set'}

    for py_file in find_python_files(root):
        tree = parse_file_safe(py_file)
        if tree is None:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is None:
                        continue

                    is_mutable = False
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        is_mutable = True
                    elif isinstance(default, ast.Call):
                        if isinstance(default.func, ast.Name) and default.func.id in mutable_types:
                            is_mutable = True

                    if is_mutable:
                        findings.append({
                            'type': 'mutable_default',
                            'file': str(py_file.relative_to(root)),
                            'line': node.lineno,
                            'name': node.name,
                            'severity': 'HIGH',
                            'fix_hint': "Use None as default, then 'if param is None: param = []' in body."
                        })
                        break  # One finding per function

    return findings


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def repo_root() -> Path:
    """Get the repository root to scan"""
    # Try to find repo root by looking for common markers
    current = Path.cwd()

    for marker in ['.git', 'pyproject.toml', 'setup.py', 'src']:
        if (current / marker).exists():
            return current

    # If running from tests directory, go up
    if current.name == 'tests':
        return current.parent

    # Default to current
    return current


@pytest.fixture
def scan_root(repo_root: Path) -> Path:
    """Get the source directory to scan"""
    # Try common source layouts
    for src_dir in ['src', 'lib', 'app', repo_root.name]:
        candidate = repo_root / src_dir
        if candidate.is_dir():
            return candidate

    return repo_root


# ============================================================================
# RESCUE TESTS - These PASS by finding problems
# ============================================================================

class TestSmellDetection:
    """
    These tests PASS when they find problems in your codebase.
    A passing test means: "We found X issues that need fixing."
    """

    def test_god_classes_detected(self, scan_root: Path):
        """Find classes that do too much (God Classes)"""
        findings = detect_god_classes(scan_root)

        # This test always passes - it reports what it found
        print(f"\n{'='*60}")
        print(f"GOD CLASS DETECTION")
        print(f"{'='*60}")
        print(f"Scanned: {scan_root}")
        print(f"Found: {len(findings)} God Classes")
        print(f"Threshold: {RescueConfig.GOD_CLASS_MIN_METHODS} methods OR {RescueConfig.GOD_CLASS_MIN_LINES} lines")

        if findings:
            print(f"\n{'='*60}")
            for f in sorted(findings, key=lambda x: -x['lines']):
                print(f"\n  {f['severity']} | {f['file']}:{f['line']}")
                print(f"    Class: {f['name']}")
                print(f"    Size: {f['methods']} methods, {f['lines']} lines")
                print(f"    Fix: {f['fix_hint']}")

        # Store for rescue plan
        pytest.rescue_findings = getattr(pytest, 'rescue_findings', {})
        pytest.rescue_findings['god_classes'] = findings

    def test_god_functions_detected(self, scan_root: Path):
        """Find functions that are too long (God Functions)"""
        findings = detect_god_functions(scan_root)

        print(f"\n{'='*60}")
        print(f"GOD FUNCTION DETECTION")
        print(f"{'='*60}")
        print(f"Found: {len(findings)} God Functions")
        print(f"Threshold: {RescueConfig.GOD_FUNCTION_MIN_LINES} lines")

        if findings:
            print(f"\n{'='*60}")
            for f in sorted(findings, key=lambda x: -x['lines'])[:20]:  # Top 20
                print(f"\n  {f['severity']} | {f['file']}:{f['line']}")
                print(f"    Function: {f['name']}")
                print(f"    Lines: {f['lines']}")
                print(f"    Fix: {f['fix_hint']}")

        pytest.rescue_findings = getattr(pytest, 'rescue_findings', {})
        pytest.rescue_findings['god_functions'] = findings

    def test_deep_nesting_detected(self, scan_root: Path):
        """Find deeply nested code (Arrow Anti-Pattern)"""
        findings = detect_deep_nesting(scan_root)

        print(f"\n{'='*60}")
        print(f"DEEP NESTING DETECTION")
        print(f"{'='*60}")
        print(f"Found: {len(findings)} deeply nested functions")
        print(f"Threshold: {RescueConfig.MAX_NESTING_DEPTH} levels")

        if findings:
            print(f"\n{'='*60}")
            for f in sorted(findings, key=lambda x: -x['depth'])[:15]:
                print(f"\n  {f['severity']} | {f['file']}:{f['line']}")
                print(f"    Function: {f['name']}")
                print(f"    Depth: {f['depth']} levels")
                print(f"    Fix: {f['fix_hint']}")

        pytest.rescue_findings = getattr(pytest, 'rescue_findings', {})
        pytest.rescue_findings['deep_nesting'] = findings

    def test_long_parameter_lists_detected(self, scan_root: Path):
        """Find functions with too many parameters"""
        findings = detect_long_parameter_lists(scan_root)

        print(f"\n{'='*60}")
        print(f"LONG PARAMETER LIST DETECTION")
        print(f"{'='*60}")
        print(f"Found: {len(findings)} functions with too many params")
        print(f"Threshold: {RescueConfig.MAX_PARAMETERS} parameters")

        if findings:
            print(f"\n{'='*60}")
            for f in sorted(findings, key=lambda x: -x['param_count'])[:15]:
                print(f"\n  {f['severity']} | {f['file']}:{f['line']}")
                print(f"    Function: {f['name']}")
                print(f"    Params: {f['param_count']} ({', '.join(f['params'][:5])}...)")
                print(f"    Fix: {f['fix_hint']}")

        pytest.rescue_findings = getattr(pytest, 'rescue_findings', {})
        pytest.rescue_findings['long_params'] = findings

    def test_large_files_detected(self, scan_root: Path):
        """Find files that should be split"""
        findings = detect_large_files(scan_root)

        print(f"\n{'='*60}")
        print(f"LARGE FILE DETECTION")
        print(f"{'='*60}")
        print(f"Found: {len(findings)} oversized files")
        print(f"Threshold: {RescueConfig.LARGE_FILE_LINES} lines")

        if findings:
            print(f"\n{'='*60}")
            for f in sorted(findings, key=lambda x: -x['lines']):
                print(f"\n  {f['severity']} | {f['file']}")
                print(f"    Lines: {f['lines']}")
                print(f"    Fix: {f['fix_hint']}")

        pytest.rescue_findings = getattr(pytest, 'rescue_findings', {})
        pytest.rescue_findings['large_files'] = findings

    def test_bare_excepts_detected(self, scan_root: Path):
        """Find bare except clauses that hide bugs"""
        findings = detect_bare_excepts(scan_root)

        print(f"\n{'='*60}")
        print(f"BARE EXCEPT DETECTION")
        print(f"{'='*60}")
        print(f"Found: {len(findings)} bare except clauses")

        if findings:
            print(f"\n{'='*60}")
            for f in findings[:20]:
                print(f"\n  {f['severity']} | {f['file']}:{f['line']}")
                print(f"    Fix: {f['fix_hint']}")

        pytest.rescue_findings = getattr(pytest, 'rescue_findings', {})
        pytest.rescue_findings['bare_excepts'] = findings

    def test_mutable_defaults_detected(self, scan_root: Path):
        """Find mutable default arguments"""
        findings = detect_mutable_defaults(scan_root)

        print(f"\n{'='*60}")
        print(f"MUTABLE DEFAULT DETECTION")
        print(f"{'='*60}")
        print(f"Found: {len(findings)} mutable default arguments")

        if findings:
            print(f"\n{'='*60}")
            for f in findings[:20]:
                print(f"\n  {f['severity']} | {f['file']}:{f['line']}")
                print(f"    Function: {f['name']}")
                print(f"    Fix: {f['fix_hint']}")

        pytest.rescue_findings = getattr(pytest, 'rescue_findings', {})
        pytest.rescue_findings['mutable_defaults'] = findings


class TestRescueSummary:
    """Generate a summary of all findings"""

    def test_generate_rescue_summary(self, scan_root: Path):
        """Compile all findings into a rescue plan"""

        # Run all detectors
        all_findings = {
            'god_classes': detect_god_classes(scan_root),
            'god_functions': detect_god_functions(scan_root),
            'deep_nesting': detect_deep_nesting(scan_root),
            'long_params': detect_long_parameter_lists(scan_root),
            'large_files': detect_large_files(scan_root),
            'bare_excepts': detect_bare_excepts(scan_root),
            'mutable_defaults': detect_mutable_defaults(scan_root),
        }

        total = sum(len(v) for v in all_findings.values())
        high_severity = sum(1 for v in all_findings.values() for f in v if f.get('severity') == 'HIGH')

        print(f"\n{'='*60}")
        print(f"RESCUE MISSION SUMMARY")
        print(f"{'='*60}")
        print(f"\nScanned: {scan_root}")
        print(f"Total Issues: {total}")
        print(f"High Severity: {high_severity}")
        print(f"\nBreakdown:")

        for smell_type, findings in all_findings.items():
            status = "CLEAN" if len(findings) == 0 else f"{len(findings)} issues"
            print(f"  - {smell_type.replace('_', ' ').title()}: {status}")

        # Priority order for fixes
        print(f"\n{'='*60}")
        print(f"RECOMMENDED FIX ORDER")
        print(f"{'='*60}")

        priority = [
            ('bare_excepts', 'CRITICAL - These hide bugs'),
            ('mutable_defaults', 'CRITICAL - These cause subtle bugs'),
            ('large_files', 'HIGH - Split these first'),
            ('god_classes', 'HIGH - Then break up classes'),
            ('god_functions', 'MEDIUM - Extract helper functions'),
            ('deep_nesting', 'MEDIUM - Flatten with early returns'),
            ('long_params', 'LOW - Group into dataclasses'),
        ]

        print()
        for i, (smell_type, reason) in enumerate(priority, 1):
            count = len(all_findings[smell_type])
            if count > 0:
                print(f"  {i}. {smell_type} ({count}) - {reason}")

        # Estimate effort
        effort_hours = (
            len(all_findings['large_files']) * 4 +
            len(all_findings['god_classes']) * 3 +
            len(all_findings['god_functions']) * 1 +
            len(all_findings['deep_nesting']) * 0.5 +
            len(all_findings['long_params']) * 0.5 +
            len(all_findings['bare_excepts']) * 0.25 +
            len(all_findings['mutable_defaults']) * 0.25
        )

        print(f"\n{'='*60}")
        print(f"ESTIMATED EFFORT: {effort_hours:.1f} hours")
        print(f"{'='*60}")


# ============================================================================
# MAIN - Run standalone
# ============================================================================

if __name__ == '__main__':
    # Run with pytest
    pytest.main([__file__, '-v', '--tb=short', '-s'])
