#!/usr/bin/env python3
"""
vue_decomposition_analyzer.py - Analyze Vue components for decomposition candidates

This tool identifies large Vue components that would benefit from extracting
logic into composables (Vue 3 Composition API pattern).

Usage:
    python scripts/vue_decomposition_analyzer.py <vue_src_path> [--threshold 200] [--output json|markdown]

Example:
    python scripts/vue_decomposition_analyzer.py ./packages/client/src --threshold 250

Methodology:
    1. Find all .vue files
    2. Extract <script setup> section and count LOC (excluding comments/blanks)
    3. Check if component already uses composables (imports use*.ts)
    4. Flag components exceeding threshold that lack composable extraction
    5. Generate decomposition recommendations

Output:
    - List of decomposition candidates with script LOC
    - Suggested composable extractions based on code patterns
    - Summary statistics
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class VueComponentAnalysis:
    """Analysis result for a single Vue component."""
    file_path: str
    total_loc: int
    script_loc: int
    template_loc: int
    style_loc: int
    has_composables: bool
    composable_imports: list[str] = field(default_factory=list)
    detected_patterns: list[str] = field(default_factory=list)
    suggested_extractions: list[str] = field(default_factory=list)


def count_effective_loc(code: str) -> int:
    """Count lines of code excluding comments and blank lines."""
    lines = code.split('\n')
    effective = 0
    in_block_comment = False

    for line in lines:
        stripped = line.strip()

        # Handle block comments
        if '/*' in stripped and '*/' in stripped:
            # Single-line block comment
            continue
        elif '/*' in stripped:
            in_block_comment = True
            continue
        elif '*/' in stripped:
            in_block_comment = False
            continue

        if in_block_comment:
            continue

        # Skip empty lines and single-line comments
        if not stripped or stripped.startswith('//') or stripped.startswith('*'):
            continue

        effective += 1

    return effective


def extract_section(content: str, tag: str) -> str:
    """Extract content between <tag> and </tag>."""
    # Handle script setup specifically
    if tag == 'script':
        pattern = r'<script[^>]*>(.*?)</script>'
    else:
        pattern = rf'<{tag}[^>]*>(.*?)</{tag}>'

    match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
    return match.group(1) if match else ''


def detect_code_patterns(script_content: str) -> list[str]:
    """Detect common patterns that suggest extraction opportunities."""
    patterns = []

    # State management patterns
    if re.search(r'\bref\s*<.*>\s*\(', script_content) and script_content.count('ref') > 5:
        patterns.append('heavy_state')

    # Computed properties
    if script_content.count('computed(') > 3:
        patterns.append('multiple_computed')

    # Watch patterns
    if script_content.count('watch(') > 2 or script_content.count('watchEffect(') > 1:
        patterns.append('multiple_watchers')

    # API/fetch patterns
    if re.search(r'(fetch|axios|api\(|\.get\(|\.post\()', script_content, re.IGNORECASE):
        patterns.append('api_calls')

    # Event handlers
    handler_count = len(re.findall(r'function\s+\w+|const\s+\w+\s*=\s*(?:async\s*)?\(', script_content))
    if handler_count > 5:
        patterns.append('many_handlers')

    # Export/download patterns
    if re.search(r'(download|export|blob|createObjectURL)', script_content, re.IGNORECASE):
        patterns.append('export_functions')

    # Form/validation patterns
    if re.search(r'(validate|validation|errors|isValid)', script_content, re.IGNORECASE):
        patterns.append('form_validation')

    # Filtering/sorting patterns
    if re.search(r'(filter|sort|search|paginate)', script_content, re.IGNORECASE):
        patterns.append('filtering_sorting')

    return patterns


def suggest_extractions(patterns: list[str], component_name: str) -> list[str]:
    """Suggest composable names based on detected patterns."""
    suggestions = []
    base_name = component_name.replace('.vue', '')

    pattern_to_composable = {
        'heavy_state': f'use{base_name}State',
        'multiple_computed': f'use{base_name}Computed',
        'multiple_watchers': f'use{base_name}Watchers',
        'api_calls': f'use{base_name}Api',
        'many_handlers': f'use{base_name}Actions',
        'export_functions': f'use{base_name}Export',
        'form_validation': f'use{base_name}Validation',
        'filtering_sorting': f'use{base_name}Filters',
    }

    for pattern in patterns:
        if pattern in pattern_to_composable:
            suggestions.append(pattern_to_composable[pattern])

    return suggestions


def analyze_vue_file(file_path: Path) -> VueComponentAnalysis:
    """Analyze a single Vue file."""
    content = file_path.read_text(encoding='utf-8', errors='replace')

    # Extract sections
    script_content = extract_section(content, 'script')
    template_content = extract_section(content, 'template')
    style_content = extract_section(content, 'style')

    # Count LOC
    total_loc = len(content.split('\n'))
    script_loc = count_effective_loc(script_content)
    template_loc = count_effective_loc(template_content)
    style_loc = count_effective_loc(style_content)

    # Check for composable imports
    composable_pattern = r"from\s+['\"].*?/use\w+['\"]|import\s+.*use\w+.*from"
    composable_imports = re.findall(r'use\w+', ' '.join(re.findall(composable_pattern, script_content)))
    has_composables = len(composable_imports) > 0

    # Detect patterns and suggest extractions
    patterns = detect_code_patterns(script_content)
    suggestions = suggest_extractions(patterns, file_path.name)

    return VueComponentAnalysis(
        file_path=str(file_path),
        total_loc=total_loc,
        script_loc=script_loc,
        template_loc=template_loc,
        style_loc=style_loc,
        has_composables=has_composables,
        composable_imports=composable_imports,
        detected_patterns=patterns,
        suggested_extractions=suggestions,
    )


def analyze_directory(src_path: Path, threshold: int) -> list[VueComponentAnalysis]:
    """Analyze all Vue files in a directory."""
    results = []

    for vue_file in src_path.rglob('*.vue'):
        try:
            analysis = analyze_vue_file(vue_file)
            results.append(analysis)
        except Exception as e:
            print(f"Warning: Failed to analyze {vue_file}: {e}", file=sys.stderr)

    return results


def filter_candidates(results: list[VueComponentAnalysis], threshold: int) -> list[VueComponentAnalysis]:
    """Filter to decomposition candidates (large script, no composables)."""
    return [
        r for r in results
        if r.script_loc >= threshold and not r.has_composables
    ]


def generate_markdown_report(results: list[VueComponentAnalysis], candidates: list[VueComponentAnalysis], threshold: int) -> str:
    """Generate a markdown report."""
    lines = [
        "# Vue Component Decomposition Analysis",
        "",
        f"**Threshold:** {threshold} script LOC",
        f"**Total components analyzed:** {len(results)}",
        f"**Decomposition candidates:** {len(candidates)}",
        "",
        "## Summary Statistics",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Components with composables | {sum(1 for r in results if r.has_composables)} |",
        f"| Components without composables | {sum(1 for r in results if not r.has_composables)} |",
        f"| Components > {threshold} script LOC | {sum(1 for r in results if r.script_loc >= threshold)} |",
        f"| **Candidates (large + no composables)** | **{len(candidates)}** |",
        "",
    ]

    if candidates:
        lines.extend([
            "## Decomposition Candidates",
            "",
            "| Component | Script LOC | Patterns | Suggested Extractions |",
            "|-----------|------------|----------|----------------------|",
        ])

        # Sort by script LOC descending
        for c in sorted(candidates, key=lambda x: -x.script_loc):
            patterns = ', '.join(c.detected_patterns) or '-'
            suggestions = ', '.join(c.suggested_extractions) or '-'
            rel_path = Path(c.file_path).name
            lines.append(f"| `{rel_path}` | {c.script_loc} | {patterns} | {suggestions} |")

        lines.extend([
            "",
            "## Detailed Recommendations",
            "",
        ])

        for c in sorted(candidates, key=lambda x: -x.script_loc):
            rel_path = Path(c.file_path).name
            lines.extend([
                f"### {rel_path}",
                "",
                f"- **Script LOC:** {c.script_loc}",
                f"- **Total LOC:** {c.total_loc}",
                f"- **Detected patterns:** {', '.join(c.detected_patterns) or 'None'}",
                "",
            ])

            if c.suggested_extractions:
                lines.append("**Suggested composables:**")
                for s in c.suggested_extractions:
                    lines.append(f"- `{s}.ts`")
                lines.append("")

    return '\n'.join(lines)


def generate_json_report(results: list[VueComponentAnalysis], candidates: list[VueComponentAnalysis], threshold: int) -> str:
    """Generate a JSON report."""
    report = {
        "threshold": threshold,
        "total_components": len(results),
        "candidates_count": len(candidates),
        "summary": {
            "with_composables": sum(1 for r in results if r.has_composables),
            "without_composables": sum(1 for r in results if not r.has_composables),
            "above_threshold": sum(1 for r in results if r.script_loc >= threshold),
        },
        "candidates": [
            {
                "file": c.file_path,
                "script_loc": c.script_loc,
                "total_loc": c.total_loc,
                "patterns": c.detected_patterns,
                "suggested_extractions": c.suggested_extractions,
            }
            for c in sorted(candidates, key=lambda x: -x.script_loc)
        ],
    }
    return json.dumps(report, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Vue components for decomposition candidates",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("path", type=Path, help="Path to Vue source directory")
    parser.add_argument("--threshold", type=int, default=200,
                        help="Script LOC threshold for candidates (default: 200)")
    parser.add_argument("--output", choices=["json", "markdown"], default="markdown",
                        help="Output format (default: markdown)")
    parser.add_argument("--all", action="store_true",
                        help="Include all components, not just candidates")

    args = parser.parse_args()

    if not args.path.exists():
        print(f"Error: Path {args.path} does not exist", file=sys.stderr)
        sys.exit(1)

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
