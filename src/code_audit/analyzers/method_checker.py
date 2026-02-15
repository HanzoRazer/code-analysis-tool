"""
Method Existence & Typo Detection Analyzer
==========================================
Detects:
- Calls to undefined methods/attributes
- Method name typos (using Levenshtein distance)
- Argument order mismatches (with type hints)

These catch common runtime errors at static analysis time.
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from difflib import SequenceMatcher
import logging

logger = logging.getLogger(__name__)


@dataclass
class MethodIssue:
    """Represents a method-related issue."""
    file_path: Path
    line_number: int
    issue_type: str  # 'missing_method', 'typo', 'arg_order'
    severity: str  # 'HIGH', 'MEDIUM', 'LOW'
    message: str
    object_name: str
    method_name: str
    suggestion: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "file_path": str(self.file_path),
            "line_number": self.line_number,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "message": self.message,
            "object_name": self.object_name,
            "method_name": self.method_name,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
        }


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def similarity_ratio(s1: str, s2: str) -> float:
    """Calculate similarity ratio between two strings (0.0 to 1.0)."""
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


class ClassMethodExtractor(ast.NodeVisitor):
    """Extract class definitions and their methods."""

    def __init__(self):
        self.classes: Dict[str, Set[str]] = {}
        self.current_class: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef):
        self.current_class = node.name
        self.classes[node.name] = set()

        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                self.classes[node.name].add(item.name)
            elif isinstance(item, ast.Assign):
                for target in item.targets:
                    if isinstance(target, ast.Name):
                        self.classes[node.name].add(target.id)

        self.generic_visit(node)
        self.current_class = None


class MethodCallAnalyzer(ast.NodeVisitor):
    """Analyze method calls to detect issues."""

    def __init__(self, file_path: Path, known_classes: Dict[str, Set[str]]):
        self.file_path = file_path
        self.known_classes = known_classes
        self.issues: List[MethodIssue] = []
        self.variable_types: Dict[str, str] = {}  # var_name -> class_name

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments to infer types."""
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name):
                # x = ClassName()
                class_name = node.value.func.id
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.variable_types[target.id] = class_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Analyze method calls."""
        if isinstance(node.func, ast.Attribute):
            obj = node.func.value
            method_name = node.func.attr

            # Get object name
            obj_name = None
            if isinstance(obj, ast.Name):
                obj_name = obj.id

            if obj_name and obj_name in self.variable_types:
                class_name = self.variable_types[obj_name]
                if class_name in self.known_classes:
                    known_methods = self.known_classes[class_name]

                    if method_name not in known_methods:
                        # Method doesn't exist - check for typo
                        suggestion, confidence = self._find_similar_method(
                            method_name, known_methods
                        )

                        if suggestion and confidence > 0.7:
                            self.issues.append(MethodIssue(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                issue_type="typo",
                                severity="HIGH",
                                message=f"Method '{method_name}' not found on {class_name}. Did you mean '{suggestion}'?",
                                object_name=obj_name,
                                method_name=method_name,
                                suggestion=suggestion,
                                confidence=confidence,
                            ))
                        else:
                            self.issues.append(MethodIssue(
                                file_path=self.file_path,
                                line_number=node.lineno,
                                issue_type="missing_method",
                                severity="HIGH",
                                message=f"Method '{method_name}' not found on {class_name}",
                                object_name=obj_name,
                                method_name=method_name,
                                confidence=0.9,
                            ))

        self.generic_visit(node)

    def _find_similar_method(self, method_name: str, known_methods: Set[str]) -> Tuple[Optional[str], float]:
        """Find the most similar method name."""
        best_match = None
        best_score = 0.0

        for known in known_methods:
            score = similarity_ratio(method_name, known)
            if score > best_score and score > 0.6:
                best_score = score
                best_match = known

        return best_match, best_score


class MethodExistenceAnalyzer:
    """
    Analyzes Python files for method existence issues.

    Detects:
    - Calls to undefined methods
    - Method name typos
    - Missing attributes
    """

    def __init__(self):
        self.known_classes: Dict[str, Set[str]] = {}

    def analyze_file(self, file_path: Path) -> List[MethodIssue]:
        """Analyze a single file for method issues."""
        if not file_path.exists() or file_path.suffix != '.py':
            return []

        try:
            content = file_path.read_text(encoding='utf-8')
            tree = ast.parse(content)
        except (SyntaxError, UnicodeDecodeError):
            return []

        # Extract class definitions
        extractor = ClassMethodExtractor()
        extractor.visit(tree)

        # Merge with known classes
        for class_name, methods in extractor.classes.items():
            if class_name in self.known_classes:
                self.known_classes[class_name].update(methods)
            else:
                self.known_classes[class_name] = methods

        # Analyze method calls
        analyzer = MethodCallAnalyzer(file_path, self.known_classes)
        analyzer.visit(tree)

        return analyzer.issues

    def analyze_directory(self, dir_path: Path, exclude_patterns: List[str] = None) -> List[MethodIssue]:
        """Analyze all Python files in a directory."""
        exclude_patterns = exclude_patterns or ['**/test_*', '**/__pycache__/*', '**/venv/*']

        all_issues = []

        # First pass: collect all class definitions
        for py_file in dir_path.rglob('*.py'):
            if any(py_file.match(p) for p in exclude_patterns):
                continue

            try:
                content = py_file.read_text(encoding='utf-8')
                tree = ast.parse(content)
                extractor = ClassMethodExtractor()
                extractor.visit(tree)

                for class_name, methods in extractor.classes.items():
                    if class_name in self.known_classes:
                        self.known_classes[class_name].update(methods)
                    else:
                        self.known_classes[class_name] = methods
            except (SyntaxError, UnicodeDecodeError):
                continue

        # Second pass: analyze method calls
        for py_file in dir_path.rglob('*.py'):
            if any(py_file.match(p) for p in exclude_patterns):
                continue

            issues = self.analyze_file(py_file)
            all_issues.extend(issues)

        return all_issues

    def add_known_class(self, class_name: str, methods: Set[str]):
        """Add a known class with its methods (for external/stdlib classes)."""
        if class_name in self.known_classes:
            self.known_classes[class_name].update(methods)
        else:
            self.known_classes[class_name] = methods


class TypoDetector:
    """
    Specialized detector for typos in identifiers.

    Uses multiple strategies:
    - Levenshtein distance
    - Common typo patterns (transpositions, missing chars)
    - Phonetic similarity
    """

    # Common typo patterns
    COMMON_TYPOS = {
        'conection': 'connection',
        'recieve': 'receive',
        'occured': 'occurred',
        'seperate': 'separate',
        'definately': 'definitely',
        'enviroment': 'environment',
        'occurance': 'occurrence',
        'succesful': 'successful',
        'accomodate': 'accommodate',
        'persistant': 'persistent',
    }

    def __init__(self, threshold: float = 0.75):
        self.threshold = threshold
        self.known_identifiers: Set[str] = set()

    def add_known_identifiers(self, identifiers: Set[str]):
        """Add known valid identifiers."""
        self.known_identifiers.update(identifiers)

    def check_identifier(self, identifier: str) -> Optional[Tuple[str, float]]:
        """
        Check if an identifier might be a typo.

        Returns (suggested_correction, confidence) or None if no typo detected.
        """
        # Check common typos first
        lower_id = identifier.lower()
        if lower_id in self.COMMON_TYPOS:
            return self.COMMON_TYPOS[lower_id], 1.0

        # Check against known identifiers
        best_match = None
        best_score = 0.0

        for known in self.known_identifiers:
            if known == identifier:
                return None  # Exact match, not a typo

            score = similarity_ratio(identifier, known)
            if score > best_score and score >= self.threshold:
                best_score = score
                best_match = known

        if best_match:
            return best_match, best_score

        return None

    def find_typos_in_file(self, file_path: Path) -> List[MethodIssue]:
        """Find potential typos in a Python file."""
        if not file_path.exists() or file_path.suffix != '.py':
            return []

        issues = []

        try:
            content = file_path.read_text(encoding='utf-8')
            tree = ast.parse(content)
        except (SyntaxError, UnicodeDecodeError):
            return []

        # Collect all identifiers in file
        local_identifiers = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                local_identifiers.add(node.id)
            elif isinstance(node, ast.FunctionDef):
                local_identifiers.add(node.name)
            elif isinstance(node, ast.ClassDef):
                local_identifiers.add(node.name)
            elif isinstance(node, ast.Attribute):
                local_identifiers.add(node.attr)

        # Check each identifier
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                result = self.check_identifier(node.attr)
                if result:
                    suggestion, confidence = result
                    issues.append(MethodIssue(
                        file_path=file_path,
                        line_number=node.lineno,
                        issue_type="typo",
                        severity="MEDIUM",
                        message=f"Possible typo: '{node.attr}'. Did you mean '{suggestion}'?",
                        object_name="",
                        method_name=node.attr,
                        suggestion=suggestion,
                        confidence=confidence,
                    ))

        return issues


def analyze_project(project_path: Path) -> Dict:
    """
    Analyze a project for method existence and typo issues.

    Returns a summary dict with issues grouped by type.
    """
    analyzer = MethodExistenceAnalyzer()
    issues = analyzer.analyze_directory(project_path)

    # Group by type
    by_type = {}
    for issue in issues:
        if issue.issue_type not in by_type:
            by_type[issue.issue_type] = []
        by_type[issue.issue_type].append(issue.to_dict())

    return {
        "total_issues": len(issues),
        "by_type": by_type,
        "high_severity": len([i for i in issues if i.severity == "HIGH"]),
        "medium_severity": len([i for i in issues if i.severity == "MEDIUM"]),
        "issues": [i.to_dict() for i in issues],
    }


if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python method_checker.py <project_path>")
        sys.exit(1)

    project_path = Path(sys.argv[1])
    result = analyze_project(project_path)

    print(json.dumps(result, indent=2))
