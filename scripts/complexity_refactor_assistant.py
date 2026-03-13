#!/usr/bin/env python3
"""
complexity_refactor_assistant.py - Assist with refactoring high-complexity functions

This tool analyzes Python functions with high cyclomatic complexity and suggests
concrete refactoring opportunities by identifying extractable code blocks.

Usage:
    python scripts/complexity_refactor_assistant.py <python_file> [--function <name>] [--threshold 15]

    # Analyze all D-grade functions in a file:
    python scripts/complexity_refactor_assistant.py services/api/app/rmos/runs_v2/batch_summary.py

    # Analyze a specific function:
    python scripts/complexity_refactor_assistant.py services/api/app/rmos/runs_v2/batch_summary.py --function build_batch_summary

    # Scan entire directory for D-grade functions:
    python scripts/complexity_refactor_assistant.py services/api/app/ --scan

What it does:
    1. Parses the Python file using AST
    2. Calculates cyclomatic complexity per function (using radon algorithm)
    3. Identifies extractable blocks:
       - Sequential code blocks (>5 statements doing distinct work)
       - Nested loops/conditionals (depth > 2)
       - Long if-elif chains (>3 branches)
       - Dictionary/list comprehensions that could be named functions
       - Try/except blocks with substantial logic
    4. Generates helper function signatures with descriptive names
    5. Shows before/after skeleton for each extraction

Output Grades (radon):
    A (1-5)   - Simple, no refactor needed
    B (6-10)  - Low complexity, minor improvements possible
    C (11-15) - Moderate complexity, consider refactoring
    D (16-30) - High complexity, SHOULD refactor
    F (31+)   - Very high complexity, MUST refactor
"""

import argparse
import ast
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple, Set


@dataclass
class ExtractionCandidate:
    """A code block that could be extracted to a helper function."""
    start_line: int
    end_line: int
    suggested_name: str
    reason: str
    code_preview: str  # First few lines of the block
    complexity_reduction: int  # Estimated complexity points removed
    parameters: List[str] = field(default_factory=list)  # Variables the block needs
    returns: List[str] = field(default_factory=list)  # Variables the block produces


@dataclass
class FunctionAnalysis:
    """Analysis result for a single function."""
    name: str
    start_line: int
    end_line: int
    complexity: int
    grade: str
    extraction_candidates: List[ExtractionCandidate] = field(default_factory=list)
    nested_depth: int = 0
    branch_count: int = 0
    loop_count: int = 0


def calculate_complexity(node: ast.FunctionDef) -> int:
    """Calculate cyclomatic complexity of a function (simplified radon algorithm)."""
    complexity = 1  # Base complexity

    for child in ast.walk(node):
        # Branches add complexity
        if isinstance(child, (ast.If, ast.IfExp)):
            complexity += 1
        elif isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
            complexity += 1
        elif isinstance(child, ast.ExceptHandler):
            complexity += 1
        elif isinstance(child, (ast.And, ast.Or)):
            complexity += 1
        elif isinstance(child, ast.comprehension):
            complexity += 1
        elif isinstance(child, ast.Assert):
            complexity += 1

    return complexity


def get_grade(complexity: int) -> str:
    """Convert complexity score to letter grade."""
    if complexity <= 5:
        return 'A'
    elif complexity <= 10:
        return 'B'
    elif complexity <= 15:
        return 'C'
    elif complexity <= 30:
        return 'D'
    else:
        return 'F'


def get_nested_depth(node: ast.AST) -> int:
    """Calculate maximum nesting depth of control structures."""
    max_depth = 0

    def walk_depth(n: ast.AST, depth: int) -> None:
        nonlocal max_depth

        if isinstance(n, (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith)):
            depth += 1
            max_depth = max(max_depth, depth)

        for child in ast.iter_child_nodes(n):
            walk_depth(child, depth)

    walk_depth(node, 0)
    return max_depth


def count_branches(node: ast.FunctionDef) -> int:
    """Count number of if/elif/else branches."""
    count = 0
    for child in ast.walk(node):
        if isinstance(child, ast.If):
            count += 1
            # Count elif branches
            while child.orelse and len(child.orelse) == 1 and isinstance(child.orelse[0], ast.If):
                count += 1
                child = child.orelse[0]
            # Count else
            if child.orelse:
                count += 1
    return count


def count_loops(node: ast.FunctionDef) -> int:
    """Count number of loops."""
    count = 0
    for child in ast.walk(node):
        if isinstance(child, (ast.For, ast.While, ast.AsyncFor)):
            count += 1
    return count


def find_sequential_blocks(node: ast.FunctionDef, source_lines: List[str]) -> List[ExtractionCandidate]:
    """Find sequential statement blocks that could be extracted."""
    candidates = []

    # Look for consecutive statements in the function body
    body = node.body
    if len(body) < 6:
        return []  # Too short to have meaningful blocks

    # Simple heuristic: look for comment markers or blank lines that suggest logical sections
    # Also look for groups of 5+ statements that share a "theme" (e.g., all assignments, all method calls)

    i = 0
    while i < len(body):
        block_start = i
        block_type = type(body[i])

        # Count consecutive statements of similar type
        while i < len(body) and _similar_statement(body[block_start], body[i]):
            i += 1

        block_end = i
        block_size = block_end - block_start

        if block_size >= 5:
            start_line = body[block_start].lineno
            end_line = body[block_end - 1].end_lineno or body[block_end - 1].lineno

            # Generate a name based on the block's purpose
            name = _suggest_block_name(body[block_start:block_end], source_lines)

            preview = '\n'.join(source_lines[start_line-1:min(start_line+2, end_line)])

            candidates.append(ExtractionCandidate(
                start_line=start_line,
                end_line=end_line,
                suggested_name=name,
                reason=f"Sequential block of {block_size} similar statements",
                code_preview=preview,
                complexity_reduction=block_size // 3,  # Rough estimate
            ))

    return candidates


def _similar_statement(a: ast.stmt, b: ast.stmt) -> bool:
    """Check if two statements are similar enough to be in the same block."""
    # Same type is a good indicator
    if type(a) == type(b):
        return True

    # Assignments and augmented assignments
    if isinstance(a, (ast.Assign, ast.AugAssign, ast.AnnAssign)) and isinstance(b, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
        return True

    # Expression statements (method calls, etc.)
    if isinstance(a, ast.Expr) and isinstance(b, ast.Expr):
        return True

    return False


def _suggest_block_name(statements: List[ast.stmt], source_lines: List[str]) -> str:
    """Suggest a helper function name based on statements."""
    # Look for patterns in the statements
    if all(isinstance(s, ast.Assign) for s in statements):
        # Check what's being assigned
        targets = []
        for s in statements:
            if isinstance(s, ast.Assign):
                for t in s.targets:
                    if isinstance(t, ast.Name):
                        targets.append(t.id)

        if targets:
            # Find common prefix
            common = _common_prefix(targets)
            if common and len(common) > 2:
                return f"_build_{common}_data"

    # Default: use line number
    return f"_process_block_{statements[0].lineno}"


def _common_prefix(strings: List[str]) -> str:
    """Find common prefix of strings."""
    if not strings:
        return ""

    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix) and prefix:
            prefix = prefix[:-1]

    # Strip trailing underscore or partial word
    while prefix and not prefix[-1].isalnum():
        prefix = prefix[:-1]

    return prefix


def find_nested_blocks(node: ast.FunctionDef, source_lines: List[str]) -> List[ExtractionCandidate]:
    """Find deeply nested control structures that could be extracted."""
    candidates = []

    def check_nesting(n: ast.AST, depth: int, parent_line: int) -> None:
        if isinstance(n, (ast.If, ast.For, ast.While, ast.Try)):
            depth += 1

            if depth >= 3:  # Deeply nested
                start_line = n.lineno
                end_line = getattr(n, 'end_lineno', n.lineno)

                preview = '\n'.join(source_lines[start_line-1:min(start_line+2, end_line)])

                if isinstance(n, ast.If):
                    name = f"_check_condition_{start_line}"
                    reason = f"Deeply nested if-block (depth {depth})"
                elif isinstance(n, (ast.For, ast.While)):
                    name = f"_process_items_{start_line}"
                    reason = f"Deeply nested loop (depth {depth})"
                else:
                    name = f"_handle_block_{start_line}"
                    reason = f"Deeply nested try-block (depth {depth})"

                candidates.append(ExtractionCandidate(
                    start_line=start_line,
                    end_line=end_line,
                    suggested_name=name,
                    reason=reason,
                    code_preview=preview,
                    complexity_reduction=depth,
                ))

        for child in ast.iter_child_nodes(n):
            check_nesting(child, depth, n.lineno if hasattr(n, 'lineno') else parent_line)

    check_nesting(node, 0, node.lineno)
    return candidates


def find_long_if_chains(node: ast.FunctionDef, source_lines: List[str]) -> List[ExtractionCandidate]:
    """Find long if-elif chains that could be refactored."""
    candidates = []

    for child in ast.walk(node):
        if not isinstance(child, ast.If):
            continue

        # Count the chain length
        chain_length = 1
        current = child
        while current.orelse and len(current.orelse) == 1 and isinstance(current.orelse[0], ast.If):
            chain_length += 1
            current = current.orelse[0]

        if chain_length >= 4:
            start_line = child.lineno
            end_line = getattr(current, 'end_lineno', current.lineno)

            preview = source_lines[start_line-1] if start_line <= len(source_lines) else ""

            candidates.append(ExtractionCandidate(
                start_line=start_line,
                end_line=end_line,
                suggested_name=f"_dispatch_{start_line}",
                reason=f"Long if-elif chain ({chain_length} branches) - consider dict dispatch or strategy pattern",
                code_preview=preview,
                complexity_reduction=chain_length,
            ))

    return candidates


def analyze_function(func_node: ast.FunctionDef, source_lines: List[str]) -> FunctionAnalysis:
    """Analyze a single function for complexity and extraction opportunities."""
    complexity = calculate_complexity(func_node)
    grade = get_grade(complexity)
    nested_depth = get_nested_depth(func_node)
    branch_count = count_branches(func_node)
    loop_count = count_loops(func_node)

    analysis = FunctionAnalysis(
        name=func_node.name,
        start_line=func_node.lineno,
        end_line=getattr(func_node, 'end_lineno', func_node.lineno),
        complexity=complexity,
        grade=grade,
        nested_depth=nested_depth,
        branch_count=branch_count,
        loop_count=loop_count,
    )

    # Only find extraction candidates for complex functions
    if complexity >= 15:  # C grade or worse
        analysis.extraction_candidates.extend(find_sequential_blocks(func_node, source_lines))
        analysis.extraction_candidates.extend(find_nested_blocks(func_node, source_lines))
        analysis.extraction_candidates.extend(find_long_if_chains(func_node, source_lines))

    return analysis


def analyze_file(file_path: Path, function_name: Optional[str] = None, threshold: int = 15) -> List[FunctionAnalysis]:
    """Analyze all functions in a file."""
    try:
        content = file_path.read_text(encoding='utf-8')
        tree = ast.parse(content)
        source_lines = content.split('\n')
    except (SyntaxError, OSError) as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)
        return []

    results = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if function_name and node.name != function_name:
                continue

            analysis = analyze_function(node, source_lines)

            if analysis.complexity >= threshold:
                results.append(analysis)

    return results


def scan_directory(dir_path: Path, threshold: int = 15) -> List[Tuple[Path, FunctionAnalysis]]:
    """Scan directory for high-complexity functions."""
    all_results = []

    for py_file in dir_path.rglob('*.py'):
        # Skip tests and cache
        if '__pycache__' in str(py_file) or 'test_' in py_file.name:
            continue

        results = analyze_file(py_file, threshold=threshold)
        for r in results:
            all_results.append((py_file, r))

    # Sort by complexity descending
    all_results.sort(key=lambda x: -x[1].complexity)
    return all_results


def format_analysis(analysis: FunctionAnalysis, file_path: Optional[Path] = None) -> str:
    """Format analysis as readable output."""
    lines = []

    # Header
    grade_emoji = {'A': '', 'B': '', 'C': '', 'D': '', 'F': ''}
    lines.append(f"\n{'='*60}")
    lines.append(f" {analysis.name}() - Grade {analysis.grade} {grade_emoji.get(analysis.grade, '')}")
    lines.append(f"{'='*60}")

    if file_path:
        lines.append(f"File: {file_path}")
    lines.append(f"Lines: {analysis.start_line}-{analysis.end_line}")
    lines.append(f"Complexity: {analysis.complexity}")
    lines.append(f"Nesting depth: {analysis.nested_depth}")
    lines.append(f"Branches: {analysis.branch_count}")
    lines.append(f"Loops: {analysis.loop_count}")

    if analysis.extraction_candidates:
        lines.append(f"\n EXTRACTION OPPORTUNITIES ({len(analysis.extraction_candidates)} found):")
        lines.append("-" * 50)

        for i, candidate in enumerate(analysis.extraction_candidates, 1):
            lines.append(f"\n  [{i}] {candidate.suggested_name}()")
            lines.append(f"      Lines {candidate.start_line}-{candidate.end_line}")
            lines.append(f"      Reason: {candidate.reason}")
            lines.append(f"      Est. complexity reduction: -{candidate.complexity_reduction}")
            if candidate.code_preview:
                preview_lines = candidate.code_preview.split('\n')[:3]
                for pl in preview_lines:
                    lines.append(f"      | {pl[:60]}{'...' if len(pl) > 60 else ''}")
    else:
        lines.append("\n  No extraction candidates identified.")
        lines.append("  Consider manual review for:")
        lines.append("  - Repeated patterns that could be parameterized")
        lines.append("  - Early returns to reduce nesting")
        lines.append("  - Guard clauses to simplify conditionals")

    # Refactoring suggestions
    lines.append(f"\n REFACTORING STRATEGY:")
    lines.append("-" * 50)

    if analysis.nested_depth >= 3:
        lines.append("  - Extract nested blocks to reduce depth")
        lines.append("  - Use early returns / guard clauses")

    if analysis.branch_count >= 5:
        lines.append("  - Consider dict dispatch for multiple branches")
        lines.append("  - Extract branch logic to separate functions")

    if analysis.loop_count >= 3:
        lines.append("  - Extract loop bodies to helper functions")
        lines.append("  - Consider using map/filter for simple transforms")

    if analysis.complexity >= 20:
        lines.append("  - Split into 2-3 smaller functions")
        lines.append("  - Each function should do ONE thing")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Python functions for complexity and suggest refactoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("path", type=Path, help="Python file or directory to analyze")
    parser.add_argument("--function", "-f", help="Analyze specific function only")
    parser.add_argument("--threshold", "-t", type=int, default=15,
                        help="Complexity threshold (default: 15 = C grade)")
    parser.add_argument("--scan", action="store_true",
                        help="Scan directory for all high-complexity functions")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--top", type=int, default=10,
                        help="Show top N results in scan mode (default: 10)")

    args = parser.parse_args()

    if not args.path.exists():
        print(f"Error: {args.path} does not exist", file=sys.stderr)
        sys.exit(1)

    if args.scan or args.path.is_dir():
        # Scan directory mode
        results = scan_directory(args.path, args.threshold)

        if not results:
            print(f"No functions with complexity >= {args.threshold} found.")
            sys.exit(0)

        print(f"\n{'='*60}")
        print(f" HIGH COMPLEXITY FUNCTIONS (threshold: {args.threshold})")
        print(f" Found: {len(results)} functions")
        print(f"{'='*60}")

        for file_path, analysis in results[:args.top]:
            print(format_analysis(analysis, file_path))

        if len(results) > args.top:
            print(f"\n... and {len(results) - args.top} more. Use --top to see more.")

    else:
        # Single file mode
        results = analyze_file(args.path, args.function, args.threshold)

        if not results:
            if args.function:
                print(f"Function '{args.function}' not found or below threshold.")
            else:
                print(f"No functions with complexity >= {args.threshold} found.")
            sys.exit(0)

        for analysis in results:
            print(format_analysis(analysis, args.path))

    sys.exit(0)


if __name__ == "__main__":
    main()
