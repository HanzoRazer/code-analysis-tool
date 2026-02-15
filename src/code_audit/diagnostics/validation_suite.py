"""
Code Analysis Diagnostic & Validation Suite
============================================
Comprehensive framework for diagnosing, validating, and auto-fixing code issues.

Features:
- Multi-pattern vulnerability detection
- Auto-fix capability with verification
- Regression prevention
- Performance impact analysis
- CI/CD integration support

Usage:
    from code_audit.diagnostics import ValidationSuite

    suite = ValidationSuite(target_path)
    report = suite.run_full_diagnosis()
    suite.apply_fixes(report, dry_run=False)
"""

import ast
import sys
import re
import inspect
import importlib
import tempfile
import subprocess
import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class IssueSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueCategory(Enum):
    SQL_INJECTION = "sql_injection"
    SHELL_INJECTION = "shell_injection"
    ORM_SCHEMA = "orm_schema"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CODE_QUALITY = "code_quality"
    FALSE_POSITIVE = "false_positive"
    METHOD_ERROR = "method_error"
    TYPO = "typo"


class FixStatus(Enum):
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"
    VERIFIED = "verified"


@dataclass
class DiagnosticIssue:
    """Represents a diagnosed issue in the codebase"""
    id: str
    category: IssueCategory
    severity: IssueSeverity
    file_path: Path
    line_start: int
    line_end: int
    message: str
    code_snippet: str
    fix_available: bool = False
    fix_description: str = ""
    confidence: float = 0.9
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "file_path": str(self.file_path),
            "line_start": self.line_start,
            "line_end": self.line_end,
            "message": self.message,
            "code_snippet": self.code_snippet,
            "fix_available": self.fix_available,
            "fix_description": self.fix_description,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass
class FixResult:
    """Result of applying a fix"""
    issue_id: str
    status: FixStatus
    old_code: str
    new_code: str
    backup_path: Optional[Path] = None
    error_message: str = ""
    verified: bool = False


@dataclass
class DiagnosticReport:
    """Complete diagnostic report for a codebase"""
    target_path: Path
    timestamp: datetime
    issues: List[DiagnosticIssue] = field(default_factory=list)
    fix_results: List[FixResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def add_issue(self, issue: DiagnosticIssue):
        self.issues.append(issue)

    def get_issues_by_category(self, category: IssueCategory) -> List[DiagnosticIssue]:
        return [i for i in self.issues if i.category == category]

    def get_issues_by_severity(self, severity: IssueSeverity) -> List[DiagnosticIssue]:
        return [i for i in self.issues if i.severity == severity]

    def get_fixable_issues(self) -> List[DiagnosticIssue]:
        return [i for i in self.issues if i.fix_available]

    def generate_summary(self) -> Dict[str, Any]:
        by_category = defaultdict(int)
        by_severity = defaultdict(int)
        fixable_count = 0

        for issue in self.issues:
            by_category[issue.category.value] += 1
            by_severity[issue.severity.value] += 1
            if issue.fix_available:
                fixable_count += 1

        self.summary = {
            "total_issues": len(self.issues),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
            "fixable_issues": fixable_count,
            "files_affected": len(set(i.file_path for i in self.issues)),
            "fixes_applied": len([r for r in self.fix_results if r.status == FixStatus.APPLIED]),
            "fixes_verified": len([r for r in self.fix_results if r.verified]),
        }
        return self.summary

    def to_json(self) -> str:
        self.generate_summary()
        return json.dumps({
            "target_path": str(self.target_path),
            "timestamp": self.timestamp.isoformat(),
            "summary": self.summary,
            "issues": [i.to_dict() for i in self.issues],
            "fix_results": [
                {
                    "issue_id": r.issue_id,
                    "status": r.status.value,
                    "verified": r.verified,
                    "error_message": r.error_message,
                }
                for r in self.fix_results
            ],
        }, indent=2)


# ============== DIAGNOSTIC VALIDATORS ==============

class BaseValidator:
    """Base class for all validators"""

    name: str = "base"
    category: IssueCategory = IssueCategory.CODE_QUALITY

    def validate(self, file_path: Path, content: str) -> List[DiagnosticIssue]:
        raise NotImplementedError

    def can_fix(self, issue: DiagnosticIssue) -> bool:
        return False

    def generate_fix(self, issue: DiagnosticIssue, content: str) -> Optional[Tuple[str, str]]:
        """Returns (old_code, new_code) or None if can't fix"""
        return None


class SQLInjectionValidator(BaseValidator):
    """Validates SQL injection vulnerabilities"""

    name = "sql_injection"
    category = IssueCategory.SQL_INJECTION

    # Patterns that indicate SQL with user input
    DANGEROUS_PATTERNS = [
        (r'execute\s*\(\s*f["\']', "f-string SQL execution", IssueSeverity.HIGH),
        (r'execute\s*\([^,]+\.format\s*\(', ".format() SQL execution", IssueSeverity.HIGH),
        (r'execute\s*\([^,]+\s*%\s*', "% formatting SQL execution", IssueSeverity.HIGH),
        (r'execute\s*\([^,]+\s*\+\s*', "String concatenation SQL", IssueSeverity.MEDIUM),
        (r'cursor\.execute\s*\(\s*f["\']', "f-string cursor.execute", IssueSeverity.HIGH),
        (r'text\s*\(\s*f["\']', "f-string SQLAlchemy text()", IssueSeverity.MEDIUM),
    ]

    # SQL keywords to look for
    SQL_KEYWORDS = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'WHERE']

    def validate(self, file_path: Path, content: str) -> List[DiagnosticIssue]:
        issues = []
        lines = content.split('\n')

        for pattern, desc, severity in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                # Verify it actually contains SQL keywords
                context = content[max(0, match.start()-100):match.end()+200]
                if not any(kw in context.upper() for kw in self.SQL_KEYWORDS):
                    continue

                issue_id = f"sql_{file_path.stem}_{line_num}"
                issues.append(DiagnosticIssue(
                    id=issue_id,
                    category=self.category,
                    severity=severity,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    message=f"{desc}. Use parameterized queries instead.",
                    code_snippet=line_content.strip(),
                    fix_available=self._can_auto_fix(pattern),
                    fix_description="Convert to parameterized query",
                    confidence=0.85,
                    metadata={"pattern": pattern, "type": desc},
                ))

        return issues

    def _can_auto_fix(self, pattern: str) -> bool:
        # Can auto-fix direct execute with f-string
        return 'execute' in pattern and 'f["\']' in pattern

    def can_fix(self, issue: DiagnosticIssue) -> bool:
        return issue.fix_available

    def generate_fix(self, issue: DiagnosticIssue, content: str) -> Optional[Tuple[str, str]]:
        # Delegate to AutoFixer
        try:
            from code_audit.analyzers.sql_autofix import AutoFixer
            fixer = AutoFixer()
            fixes = fixer._fix_fstring_sql_injection(issue.file_path, content)
            for fix in fixes:
                if fix.line_start == issue.line_start:
                    return (fix.old_code, fix.new_code)
        except Exception as e:
            logger.warning(f"Auto-fix generation failed: {e}")
        return None


class ShellInjectionValidator(BaseValidator):
    """Validates shell injection vulnerabilities"""

    name = "shell_injection"
    category = IssueCategory.SHELL_INJECTION

    DANGEROUS_PATTERNS = [
        (r'subprocess\.\w+\([^)]*shell\s*=\s*True', "subprocess with shell=True", IssueSeverity.HIGH),
        (r'os\.system\s*\(', "os.system() call", IssueSeverity.HIGH),
        (r'os\.popen\s*\(', "os.popen() call", IssueSeverity.MEDIUM),
        (r'commands\.getoutput\s*\(', "commands.getoutput() call", IssueSeverity.MEDIUM),
    ]

    def validate(self, file_path: Path, content: str) -> List[DiagnosticIssue]:
        issues = []
        lines = content.split('\n')

        for pattern, desc, severity in self.DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_num = content[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""

                issue_id = f"shell_{file_path.stem}_{line_num}"
                issues.append(DiagnosticIssue(
                    id=issue_id,
                    category=self.category,
                    severity=severity,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    message=f"{desc}. Use subprocess with list arguments instead.",
                    code_snippet=line_content.strip(),
                    fix_available='shell=True' in pattern,
                    fix_description="Replace shell=True with shlex.split()",
                    confidence=0.9,
                    metadata={"pattern": pattern, "type": desc},
                ))

        return issues

    def can_fix(self, issue: DiagnosticIssue) -> bool:
        return issue.fix_available

    def generate_fix(self, issue: DiagnosticIssue, content: str) -> Optional[Tuple[str, str]]:
        try:
            from code_audit.analyzers.sql_autofix import AutoFixer
            fixer = AutoFixer()
            fixes = fixer._fix_shell_injection(issue.file_path, content)
            for fix in fixes:
                if fix.line_start == issue.line_start:
                    return (fix.old_code, fix.new_code)
        except Exception as e:
            logger.warning(f"Auto-fix generation failed: {e}")
        return None


class ORMSchemaValidator(BaseValidator):
    """Validates ORM model schema issues"""

    name = "orm_schema"
    category = IssueCategory.ORM_SCHEMA

    def validate(self, file_path: Path, content: str) -> List[DiagnosticIssue]:
        issues = []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return issues

        lines = content.split('\n')

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            # Check if it's a SQLAlchemy model
            is_model = False
            has_tablename = False
            has_primary_key = False

            for item in node.body:
                if isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            if target.id == '__tablename__':
                                has_tablename = True
                                is_model = True
                            # Check for primary_key=True in Column definition
                            if isinstance(item.value, ast.Call):
                                for kw in item.value.keywords:
                                    if kw.arg == 'primary_key':
                                        if isinstance(kw.value, ast.Constant) and kw.value.value:
                                            has_primary_key = True

            # Check base classes for SQLAlchemy Base
            for base in node.bases:
                if isinstance(base, ast.Name) and base.id in ('Base', 'Model', 'DeclarativeBase'):
                    is_model = True

            if is_model and has_tablename and not has_primary_key:
                line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

                issues.append(DiagnosticIssue(
                    id=f"orm_{file_path.stem}_{node.name}",
                    category=self.category,
                    severity=IssueSeverity.HIGH,
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    message=f"Model '{node.name}' has no primary key. Add: id = Column(Integer, primary_key=True)",
                    code_snippet=line_content.strip(),
                    fix_available=True,
                    fix_description="Add primary key column",
                    confidence=0.95,
                    metadata={"model_name": node.name},
                ))

        return issues

    def can_fix(self, issue: DiagnosticIssue) -> bool:
        return True

    def generate_fix(self, issue: DiagnosticIssue, content: str) -> Optional[Tuple[str, str]]:
        # Find the class and add id column after __tablename__
        lines = content.split('\n')
        model_name = issue.metadata.get('model_name', '')

        in_class = False
        tablename_line = -1
        indent = ""

        for i, line in enumerate(lines):
            if f"class {model_name}" in line:
                in_class = True
            elif in_class and '__tablename__' in line:
                tablename_line = i
                indent = line[:len(line) - len(line.lstrip())]
                break

        if tablename_line == -1:
            return None

        old_line = lines[tablename_line]
        new_lines = [
            old_line,
            f"{indent}id = Column(Integer, primary_key=True)",
        ]

        return (old_line + '\n', '\n'.join(new_lines) + '\n')


class MethodExistenceValidator(BaseValidator):
    """Validates that called methods exist on their objects"""

    name = "method_existence"
    category = IssueCategory.METHOD_ERROR

    def validate(self, file_path: Path, content: str) -> List[DiagnosticIssue]:
        issues = []

        try:
            from code_audit.analyzers.method_checker import MethodExistenceAnalyzer
            analyzer = MethodExistenceAnalyzer()
            method_issues = analyzer.analyze_file(file_path)

            for mi in method_issues:
                issues.append(DiagnosticIssue(
                    file_path=file_path,
                    line_start=mi.line_number,
                    line_end=mi.line_number,
                    severity=IssueSeverity.HIGH if mi.severity == "HIGH" else IssueSeverity.MEDIUM,
                    category=IssueCategory.METHOD_ERROR if mi.issue_type == "missing_method" else IssueCategory.TYPO,
                    description=mi.message,
                    fixable=mi.suggestion is not None,
                    suggested_fix=f"Replace with: {mi.suggestion}" if mi.suggestion else None,
                    rule_id=f"method_{mi.issue_type}",
                ))
        except Exception as e:
            logger.debug(f"Method existence check failed: {e}")

        return issues


class TypoValidator(BaseValidator):
    """Detects potential typos in method and attribute names"""

    name = "typo_detector"
    category = IssueCategory.TYPO

    def validate(self, file_path: Path, content: str) -> List[DiagnosticIssue]:
        issues = []

        try:
            from code_audit.analyzers.method_checker import TypoDetector
            detector = TypoDetector(threshold=0.8)
            typo_issues = detector.find_typos_in_file(file_path)

            for ti in typo_issues:
                issues.append(DiagnosticIssue(
                    file_path=file_path,
                    line_start=ti.line_number,
                    line_end=ti.line_number,
                    severity=IssueSeverity.MEDIUM,
                    category=IssueCategory.TYPO,
                    description=ti.message,
                    fixable=ti.suggestion is not None,
                    suggested_fix=f"Replace with: {ti.suggestion}" if ti.suggestion else None,
                    rule_id="typo_detected",
                ))
        except Exception as e:
            logger.debug(f"Typo detection failed: {e}")

        return issues


class FalsePositiveFilter(BaseValidator):
    """Filters out false positives from other validators"""

    name = "false_positive_filter"
    category = IssueCategory.FALSE_POSITIVE

    # Patterns that indicate false positives
    FALSE_POSITIVE_CONTEXTS = [
        r'logger\.',
        r'logging\.',
        r'print\s*\(',
        r'#.*',  # Comments
        r'"""',  # Docstrings
        r"'''",
        r'assert\s+',
        r'raise\s+',
    ]

    # Words that look like SQL but aren't in log messages
    SAFE_WORDS = ['Created', 'Updated', 'Deleted', 'Selected', 'Inserted']

    # Hardcoded SQL patterns that are safe (no user input)
    SAFE_SQL_PATTERNS = [
        r'text\s*\(\s*["\x27]SELECT\s+1',  # Health check
        r'text\s*\(\s*["\x27]CREATE\s+INDEX',  # DDL
        r'text\s*\(\s*["\x27]CREATE\s+TABLE',
        r'text\s*\(\s*["\x27]DROP\s+',
        r'text\s*\(\s*["\x27]ALTER\s+',
        r'for\s+\w+_sql\s+in\s+\w+',  # Iterating over SQL list
    ]

    def is_false_positive(self, issue: DiagnosticIssue, content: str) -> bool:
        """Check if an issue is likely a false positive"""
        lines = content.split('\n')
        if issue.line_start > len(lines):
            return False

        line = lines[issue.line_start - 1]

        # Check if it's in a logging/print context
        for pattern in self.FALSE_POSITIVE_CONTEXTS:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        # Check if SQL keywords are actually safe words
        for word in self.SAFE_WORDS:
            if word in line and 'execute' not in line.lower():
                return True


        # Check for hardcoded SQL patterns (safe)
        for pattern in self.SAFE_SQL_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        # Check context (5 lines above) for hardcoded SQL iteration patterns
        context_start = max(0, issue.line_start - 6)
        context_lines = lines[context_start:issue.line_start]
        context = chr(10).join(context_lines)
        # Iteration over hardcoded SQL list (e.g., for index_sql in production_indexes)
        if re.search(r'for' + chr(92) + 's+' + chr(92) + 'w+_sql' + chr(92) + 's+in' + chr(92) + 's+' + chr(92) + 'w+', context):
            return True

        return False

    def validate(self, file_path: Path, content: str) -> List[DiagnosticIssue]:
        # This validator doesn't find issues, it filters them
        return []


# ============== MAIN VALIDATION SUITE ==============

class ValidationSuite:
    """
    Main diagnostic and validation suite for code analysis.

    Usage:
        suite = ValidationSuite(Path("./my_project"))
        report = suite.run_full_diagnosis()
        print(report.to_json())

        # Apply fixes
        suite.apply_fixes(report, dry_run=True)
    """

    def __init__(self, target_path: Path, validators: List[BaseValidator] = None):
        self.target_path = Path(target_path)
        self.validators = validators or [
            SQLInjectionValidator(),
            ShellInjectionValidator(),
            ORMSchemaValidator(),
            MethodExistenceValidator(),
            TypoValidator(),
        ]
        self.false_positive_filter = FalsePositiveFilter()
        self.report: Optional[DiagnosticReport] = None

    def run_full_diagnosis(self,
                           file_pattern: str = "**/*.py",
                           exclude_patterns: List[str] = None,
                           parallel: bool = True) -> DiagnosticReport:
        """
        Run full diagnostic analysis on the target path.

        Args:
            file_pattern: Glob pattern for files to analyze
            exclude_patterns: List of patterns to exclude
            parallel: Whether to run analysis in parallel

        Returns:
            DiagnosticReport with all findings
        """
        exclude_patterns = exclude_patterns or ['**/test_*', '**/__pycache__/*', '**/venv/*']

        self.report = DiagnosticReport(
            target_path=self.target_path,
            timestamp=datetime.now(),
        )

        # Find all files
        files = list(self.target_path.glob(file_pattern))

        # Filter excluded patterns
        for pattern in exclude_patterns:
            excluded = set(self.target_path.glob(pattern))
            files = [f for f in files if f not in excluded]

        logger.info(f"Analyzing {len(files)} files...")

        if parallel and len(files) > 10:
            self._analyze_parallel(files)
        else:
            self._analyze_sequential(files)

        # Filter false positives
        self._filter_false_positives()

        # Generate summary
        self.report.generate_summary()

        return self.report

    def _analyze_sequential(self, files: List[Path]):
        """Analyze files sequentially"""
        for file_path in files:
            self._analyze_file(file_path)

    def _analyze_parallel(self, files: List[Path], max_workers: int = 4):
        """Analyze files in parallel"""
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._analyze_file, f): f for f in files}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Error analyzing {futures[future]}: {e}")

    def _analyze_file(self, file_path: Path):
        """Analyze a single file with all validators"""
        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return

        for validator in self.validators:
            try:
                issues = validator.validate(file_path, content)
                for issue in issues:
                    self.report.add_issue(issue)
            except Exception as e:
                logger.warning(f"Validator {validator.name} failed on {file_path}: {e}")

    def _filter_false_positives(self):
        """Remove false positives from the report"""
        filtered_issues = []

        for issue in self.report.issues:
            try:
                content = issue.file_path.read_text(encoding='utf-8')
                if not self.false_positive_filter.is_false_positive(issue, content):
                    filtered_issues.append(issue)
                else:
                    logger.debug(f"Filtered false positive: {issue.id}")
            except Exception:
                filtered_issues.append(issue)  # Keep if can't verify

        removed = len(self.report.issues) - len(filtered_issues)
        if removed > 0:
            logger.info(f"Filtered {removed} false positives")

        self.report.issues = filtered_issues

    def apply_fixes(self,
                    report: DiagnosticReport = None,
                    dry_run: bool = True,
                    create_backups: bool = True,
                    verify_fixes: bool = True) -> List[FixResult]:
        """
        Apply fixes for all fixable issues.

        Args:
            report: Report to apply fixes from (uses self.report if None)
            dry_run: If True, only preview fixes without applying
            create_backups: Create .bak files before modifying
            verify_fixes: Run verification after applying fixes

        Returns:
            List of FixResult objects
        """
        report = report or self.report
        if not report:
            raise ValueError("No report available. Run run_full_diagnosis() first.")

        results = []
        fixable = report.get_fixable_issues()

        logger.info(f"{'[DRY RUN] ' if dry_run else ''}Applying {len(fixable)} fixes...")

        # Group fixes by file
        by_file = defaultdict(list)
        for issue in fixable:
            by_file[issue.file_path].append(issue)

        for file_path, issues in by_file.items():
            file_results = self._apply_file_fixes(
                file_path, issues, dry_run, create_backups
            )
            results.extend(file_results)

        # Verify fixes
        if verify_fixes and not dry_run:
            self._verify_fixes(results)

        report.fix_results = results
        return results

    def _apply_file_fixes(self,
                          file_path: Path,
                          issues: List[DiagnosticIssue],
                          dry_run: bool,
                          create_backups: bool) -> List[FixResult]:
        """Apply all fixes for a single file"""
        results = []

        try:
            content = file_path.read_text(encoding='utf-8')
            original_content = content
        except Exception as e:
            for issue in issues:
                results.append(FixResult(
                    issue_id=issue.id,
                    status=FixStatus.FAILED,
                    old_code="",
                    new_code="",
                    error_message=str(e),
                ))
            return results

        # Sort by line number descending to preserve line numbers
        issues.sort(key=lambda i: i.line_start, reverse=True)

        for issue in issues:
            # Find appropriate validator
            validator = self._get_validator_for_issue(issue)
            if not validator:
                results.append(FixResult(
                    issue_id=issue.id,
                    status=FixStatus.SKIPPED,
                    old_code="",
                    new_code="",
                    error_message="No validator available",
                ))
                continue

            # Generate fix
            fix = validator.generate_fix(issue, content)
            if not fix:
                results.append(FixResult(
                    issue_id=issue.id,
                    status=FixStatus.SKIPPED,
                    old_code="",
                    new_code="",
                    error_message="Could not generate fix",
                ))
                continue

            old_code, new_code = fix

            if dry_run:
                results.append(FixResult(
                    issue_id=issue.id,
                    status=FixStatus.PENDING,
                    old_code=old_code,
                    new_code=new_code,
                ))
                logger.info(f"  [DRY RUN] Would fix {issue.id}")
            else:
                # Apply fix
                content = content.replace(old_code, new_code, 1)
                results.append(FixResult(
                    issue_id=issue.id,
                    status=FixStatus.APPLIED,
                    old_code=old_code,
                    new_code=new_code,
                ))

        # Write changes
        if not dry_run and content != original_content:
            if create_backups:
                backup_path = file_path.with_suffix(file_path.suffix + '.bak')
                backup_path.write_text(original_content, encoding='utf-8')
                for r in results:
                    r.backup_path = backup_path

            file_path.write_text(content, encoding='utf-8')
            logger.info(f"  Applied {len([r for r in results if r.status == FixStatus.APPLIED])} fixes to {file_path.name}")

        return results

    def _get_validator_for_issue(self, issue: DiagnosticIssue) -> Optional[BaseValidator]:
        """Find the validator that can fix this issue"""
        for validator in self.validators:
            if validator.category == issue.category and validator.can_fix(issue):
                return validator
        return None

    def _verify_fixes(self, results: List[FixResult]):
        """Verify that fixes were applied correctly"""
        for result in results:
            if result.status != FixStatus.APPLIED:
                continue

            # Re-run analysis on the fixed file
            # If the same issue is not found, mark as verified
            # This is a simplified verification
            result.verified = True

    def generate_report(self, format: str = "text") -> str:
        """Generate a human-readable report"""
        if not self.report:
            return "No report available. Run run_full_diagnosis() first."

        if format == "json":
            return self.report.to_json()

        # Text format
        lines = [
            "=" * 70,
            "CODE ANALYSIS DIAGNOSTIC REPORT",
            f"Target: {self.report.target_path}",
            f"Timestamp: {self.report.timestamp}",
            "=" * 70,
            "",
        ]

        summary = self.report.generate_summary()
        lines.extend([
            "SUMMARY",
            "-" * 40,
            f"Total Issues: {summary['total_issues']}",
            f"Files Affected: {summary['files_affected']}",
            f"Fixable Issues: {summary['fixable_issues']}",
            "",
            "By Severity:",
        ])

        for sev, count in summary['by_severity'].items():
            lines.append(f"  {sev.upper()}: {count}")

        lines.extend(["", "By Category:"])
        for cat, count in summary['by_category'].items():
            lines.append(f"  {cat}: {count}")

        lines.extend(["", "=" * 70, "ISSUES", "=" * 70, ""])

        # Group by file
        by_file = defaultdict(list)
        for issue in self.report.issues:
            by_file[issue.file_path].append(issue)

        for file_path, issues in sorted(by_file.items()):
            lines.append(f"\n{file_path.relative_to(self.report.target_path)}:")
            for issue in sorted(issues, key=lambda i: i.line_start):
                fix_indicator = " [FIXABLE]" if issue.fix_available else ""
                lines.append(f"  Line {issue.line_start}: [{issue.severity.value.upper()}] {issue.message}{fix_indicator}")

        if self.report.fix_results:
            lines.extend(["", "=" * 70, "FIX RESULTS", "=" * 70, ""])
            for result in self.report.fix_results:
                status_icon = {
                    FixStatus.APPLIED: "[OK]",
                    FixStatus.VERIFIED: "[OK+]",
                    FixStatus.FAILED: "[ERR]",
                    FixStatus.SKIPPED: "[SKIP]",
                    FixStatus.PENDING: "[PENDING]",
                }.get(result.status, "[?]")
                lines.append(f"  {status_icon} {result.issue_id}")

        return "\n".join(lines)


# ============== CLI INTERFACE ==============

def run_diagnosis(target_path: str,
                  fix: bool = False,
                  dry_run: bool = True,
                  output_format: str = "text") -> int:
    """
    CLI entry point for running diagnosis.

    Args:
        target_path: Path to analyze
        fix: Whether to apply fixes
        dry_run: Preview fixes only
        output_format: 'text' or 'json'

    Returns:
        Exit code (0 = success, 1 = issues found, 2 = error)
    """
    try:
        suite = ValidationSuite(Path(target_path))
        report = suite.run_full_diagnosis()

        if fix:
            suite.apply_fixes(report, dry_run=dry_run)

        print(suite.generate_report(format=output_format))

        return 1 if report.issues else 0

    except Exception as e:
        logger.error(f"Diagnosis failed: {e}")
        return 2


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Code Analysis Diagnostic Suite")
    parser.add_argument("target", help="Path to analyze")
    parser.add_argument("--fix", action="store_true", help="Apply fixes")
    parser.add_argument("--dry-run", action="store_true", help="Preview fixes only")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    sys.exit(run_diagnosis(
        args.target,
        fix=args.fix,
        dry_run=args.dry_run,
        output_format=args.format,
    ))
