#!/usr/bin/env python3
"""
python_decomposition_analyzer.py - Analyze Python modules for decomposition candidates

This tool identifies large Python files that would benefit from splitting into
smaller, focused modules following single-responsibility principle.

Usage:
    python scripts/python_decomposition_analyzer.py <python_src_path> [--threshold 300] [--output json|markdown]

Example:
    python scripts/python_decomposition_analyzer.py ./services/api/app --threshold 400

Methodology:
    1. Find all .py files (excluding tests, __pycache__, migrations)
    2. Count effective LOC (excluding comments/blanks/docstrings)
    3. Detect code patterns suggesting extraction opportunities
    4. Flag files exceeding threshold
    5. Generate decomposition recommendations

Output:
    - List of decomposition candidates with LOC counts
    - Suggested module extractions based on code patterns
    - Summary statistics
"""

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PythonModuleAnalysis:
    """Analysis result for a single Python module."""
    file_path: str
    total_loc: int
    effective_loc: int
    function_count: int
    class_count: int
    method_count: int
    detected_patterns: list[str] = field(default_factory=list)
    suggested_extractions: list[str] = field(default_factory=list)
    complexity_indicators: dict = field(default_factory=dict)


def count_effective_loc(content: str) -> int:
    """Count lines of code excluding comments, blanks, and docstrings."""
    lines = content.split('\n')
    effective = 0
    in_docstring = False
    docstring_char = None

    for line in lines:
        stripped = line.strip()

        # Handle docstrings (triple quotes)
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                docstring_char = stripped[:3]
                # Check if single-line docstring
                if stripped.count(docstring_char) >= 2:
                    continue  # Single-line docstring
                in_docstring = True
                continue
        else:
            if docstring_char in stripped:
                in_docstring = False
            continue

        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            continue

        effective += 1

    return effective


def analyze_ast(content: str) -> dict:
    """Analyze Python AST for structural metrics."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {
            'function_count': 0,
            'class_count': 0,
            'method_count': 0,
            'import_count': 0,
            'decorator_count': 0,
            'exception_handlers': 0,
        }

    function_count = 0
    class_count = 0
    method_count = 0
    import_count = 0
    decorator_count = 0
    exception_handlers = 0

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            # Check if it's a method (inside a class) or top-level function
            function_count += 1
            decorator_count += len(node.decorator_list)
        elif isinstance(node, ast.ClassDef):
            class_count += 1
            # Count methods inside this class
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_count += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            import_count += 1
        elif isinstance(node, ast.ExceptHandler):
            exception_handlers += 1

    return {
        'function_count': function_count,
        'class_count': class_count,
        'method_count': method_count,
        'import_count': import_count,
        'decorator_count': decorator_count,
        'exception_handlers': exception_handlers,
    }


def detect_code_patterns(content: str, ast_metrics: dict) -> list[str]:
    """Detect common patterns that suggest extraction opportunities."""
    patterns = []

    # Many functions pattern (>10 top-level functions)
    if ast_metrics['function_count'] > 10:
        patterns.append('many_functions')

    # Heavy class pattern (class with >15 methods)
    if ast_metrics['method_count'] > 15:
        patterns.append('heavy_class')

    # HTTP handlers (FastAPI/Flask router decorators)
    router_decorators = len(re.findall(r'@router\.(get|post|put|delete|patch)', content, re.IGNORECASE))
    if router_decorators > 5:
        patterns.append('many_http_handlers')

    # Validation logic (many HTTPException raises)
    http_exceptions = len(re.findall(r'raise\s+HTTPException', content))
    if http_exceptions > 5:
        patterns.append('validation_logic')

    # Data transforms (heavy dict/list comprehensions, map/filter)
    comprehensions = len(re.findall(r'\[.*\bfor\b.*\bin\b.*\]|\{.*\bfor\b.*\bin\b.*\}', content))
    if comprehensions > 5:
        patterns.append('data_transforms')

    # Database operations (SQL/ORM patterns)
    db_patterns = len(re.findall(r'(\.query|\.execute|SELECT|INSERT|UPDATE|DELETE|\.filter\(|\.all\(\))', content, re.IGNORECASE))
    if db_patterns > 5:
        patterns.append('db_operations')

    # Schema/model definitions (Pydantic, dataclass)
    schema_defs = len(re.findall(r'class\s+\w+\s*\(\s*(BaseModel|BaseSettings)\s*\)|@dataclass', content))
    if schema_defs > 3:
        patterns.append('schema_definitions')

    # Heavy imports (>20 imports)
    if ast_metrics['import_count'] > 20:
        patterns.append('heavy_imports')

    # Exception handling (>5 try/except blocks)
    if ast_metrics['exception_handlers'] > 5:
        patterns.append('heavy_exception_handling')

    # Utility functions (many pure helper functions)
    helper_funcs = len(re.findall(r'def\s+_\w+\s*\(', content))
    if helper_funcs > 5:
        patterns.append('many_helpers')

    return patterns


def suggest_extractions(patterns: list[str], file_name: str) -> list[str]:
    """Suggest module names based on detected patterns."""
    suggestions = []
    base_name = file_name.replace('.py', '')

    pattern_to_module = {
        'many_functions': f'{base_name}_helpers.py',
        'heavy_class': f'{base_name}_service.py (split class)',
        'many_http_handlers': f'{base_name}_routes/ (split by resource)',
        'validation_logic': f'{base_name}_validators.py',
        'data_transforms': f'{base_name}_transforms.py',
        'db_operations': f'{base_name}_store.py',
        'schema_definitions': f'{base_name}_schemas.py',
        'heavy_imports': '(review circular imports)',
        'heavy_exception_handling': f'{base_name}_exceptions.py',
        'many_helpers': f'{base_name}_utils.py',
    }

    for pattern in patterns:
        if pattern in pattern_to_module:
            suggestions.append(pattern_to_module[pattern])

    return suggestions


def should_skip_file(file_path: Path) -> bool:
    """Check if file should be skipped from analysis."""
    skip_patterns = [
        '__pycache__',
        '.pyc',
        'migrations',
        'test_',
        '_test.py',
        'conftest.py',
        '__init__.py',
        '.egg-info',
        'venv',
        '.venv',
        'site-packages',
    ]
    path_str = str(file_path)
    return any(pattern in path_str for pattern in skip_patterns)


def analyze_python_file(file_path: Path) -> Optional[PythonModuleAnalysis]:
    """Analyze a single Python file."""
    if should_skip_file(file_path):
        return None

    try:
        content = file_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return None

    # Count LOC
    total_loc = len(content.split('\n'))
    effective_loc = count_effective_loc(content)

    # AST analysis
    ast_metrics = analyze_ast(content)

    # Detect patterns and suggest extractions
    patterns = detect_code_patterns(content, ast_metrics)
    suggestions = suggest_extractions(patterns, file_path.name)

    return PythonModuleAnalysis(
        file_path=str(file_path),
        total_loc=total_loc,
        effective_loc=effective_loc,
        function_count=ast_metrics['function_count'],
        class_count=ast_metrics['class_count'],
        method_count=ast_metrics['method_count'],
        detected_patterns=patterns,
        suggested_extractions=suggestions,
        complexity_indicators=ast_metrics,
    )


def analyze_directory(src_path: Path, threshold: int) -> list[PythonModuleAnalysis]:
    """Analyze all Python files in a directory."""
    results = []

    for py_file in src_path.rglob('*.py'):
        try:
            analysis = analyze_python_file(py_file)
            if analysis:
                results.append(analysis)
        except Exception as e:
            print(f"Warning: Failed to analyze {py_file}: {e}", file=sys.stderr)

    return results


def filter_candidates(results: list[PythonModuleAnalysis], threshold: int) -> list[PythonModuleAnalysis]:
    """Filter to decomposition candidates (large files with patterns)."""
    return [
        r for r in results
        if r.effective_loc >= threshold and len(r.detected_patterns) > 0
    ]


def generate_markdown_report(results: list[PythonModuleAnalysis], candidates: list[PythonModuleAnalysis], threshold: int) -> str:
    """Generate a markdown report."""
    lines = [
        "# Python Module Decomposition Analysis",
        "",
        f"**Threshold:** {threshold} effective LOC",
        f"**Total modules analyzed:** {len(results)}",
        f"**Decomposition candidates:** {len(candidates)}",
        "",
        "## Summary Statistics",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Modules > {threshold} LOC | {sum(1 for r in results if r.effective_loc >= threshold)} |",
        f"| Modules with patterns | {sum(1 for r in results if len(r.detected_patterns) > 0)} |",
        f"| **Candidates (large + patterns)** | **{len(candidates)}** |",
        f"| Total functions | {sum(r.function_count for r in results)} |",
        f"| Total classes | {sum(r.class_count for r in results)} |",
        "",
    ]

    if candidates:
        lines.extend([
            "## Decomposition Candidates",
            "",
            "| Module | Effective LOC | Functions | Patterns | Suggested Extractions |",
            "|--------|---------------|-----------|----------|----------------------|",
        ])

        # Sort by effective LOC descending
        for c in sorted(candidates, key=lambda x: -x.effective_loc):
            patterns = ', '.join(c.detected_patterns) or '-'
            suggestions = ', '.join(c.suggested_extractions[:2]) or '-'  # Limit to 2 for table width
            rel_path = Path(c.file_path).name
            lines.append(f"| `{rel_path}` | {c.effective_loc} | {c.function_count} | {patterns} | {suggestions} |")

        lines.extend([
            "",
            "## Detailed Recommendations",
            "",
        ])

        for c in sorted(candidates, key=lambda x: -x.effective_loc):
            rel_path = Path(c.file_path).name
            full_path = c.file_path
            lines.extend([
                f"### {rel_path}",
                "",
                f"- **Path:** `{full_path}`",
                f"- **Effective LOC:** {c.effective_loc}",
                f"- **Total LOC:** {c.total_loc}",
                f"- **Functions:** {c.function_count}",
                f"- **Classes:** {c.class_count}",
                f"- **Methods:** {c.method_count}",
                f"- **Detected patterns:** {', '.join(c.detected_patterns) or 'None'}",
                "",
            ])

            if c.suggested_extractions:
                lines.append("**Suggested extractions:**")
                for s in c.suggested_extractions:
                    lines.append(f"- `{s}`")
                lines.append("")

    return '\n'.join(lines)


def generate_json_report(results: list[PythonModuleAnalysis], candidates: list[PythonModuleAnalysis], threshold: int) -> str:
    """Generate a JSON report."""
    report = {
        "threshold": threshold,
        "total_modules": len(results),
        "candidates_count": len(candidates),
        "summary": {
            "above_threshold": sum(1 for r in results if r.effective_loc >= threshold),
            "with_patterns": sum(1 for r in results if len(r.detected_patterns) > 0),
            "total_functions": sum(r.function_count for r in results),
            "total_classes": sum(r.class_count for r in results),
        },
        "candidates": [
            {
                "file": c.file_path,
                "effective_loc": c.effective_loc,
                "total_loc": c.total_loc,
                "function_count": c.function_count,
                "class_count": c.class_count,
                "method_count": c.method_count,
                "patterns": c.detected_patterns,
                "suggested_extractions": c.suggested_extractions,
            }
            for c in sorted(candidates, key=lambda x: -x.effective_loc)
        ],
    }
    return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Python modules for decomposition candidates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("path", type=Path, help="Path to Python source directory")
    parser.add_argument("--threshold", type=int, default=300,
                        help="Effective LOC threshold for candidates (default: 300)")
    parser.add_argument("--output", choices=["json", "markdown"], default="markdown",
                        help="Output format (default: markdown)")
    parser.add_argument("--all", action="store_true",
                        help="Include all modules in output, not just candidates")
    parser.add_argument("--include-tests", action="store_true",
                        help="Include test files in analysis")

    args = parser.parse_args()

    if not args.path.exists():
        print(f"Error: Path {args.path} does not exist", file=sys.stderr)
        sys.exit(1)

    # Temporarily modify skip logic if --include-tests
    if args.include_tests:
        global should_skip_file
        original_skip = should_skip_file
        def should_skip_file(file_path: Path) -> bool:
            path_str = str(file_path)
            skip_patterns = ['__pycache__', '.pyc', 'migrations', '.egg-info', 'venv', '.venv', 'site-packages']
            return any(pattern in path_str for pattern in skip_patterns)

    # Analyze
    results = analyze_directory(args.path, args.threshold)
    candidates = filter_candidates(results, args.threshold)

    # Generate report
    if args.output == "json":
        print(generate_json_report(results, candidates, args.threshold))
    else:
        print(generate_markdown_report(results, candidates, args.threshold))

    # Exit with code indicating if candidates exist
    sys.exit(0 if not candidates else 1)


if __name__ == "__main__":
    main()
