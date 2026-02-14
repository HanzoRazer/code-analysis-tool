"""
RESCUE TIER: Extraction Plan Generator
=======================================
Generates concrete refactoring plans for detected smells.
Outputs step-by-step instructions a beginner can follow.

Usage:
    pytest tests/rescue/test_extraction_plan.py -v -s
"""
import pytest
from pathlib import Path
from typing import List, Dict, Any, Optional
import ast
import json
from datetime import datetime
from dataclasses import dataclass, field, asdict


# ============================================================================
# DATA MODELS
# ============================================================================

@dataclass
class ExtractionStep:
    """A single step in the extraction plan"""
    step_number: int
    action: str  # CREATE, MOVE, EXTRACT, DELETE, RENAME
    description: str
    source_file: Optional[str] = None
    target_file: Optional[str] = None
    source_lines: Optional[tuple] = None
    code_hint: Optional[str] = None
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH


@dataclass
class ExtractionPlan:
    """Complete plan for extracting/refactoring a smell"""
    smell_type: str
    smell_location: str
    severity: str
    estimated_minutes: int
    steps: List[ExtractionStep] = field(default_factory=list)
    rollback_hint: str = "git checkout -- ."
    test_command: str = "pytest"


@dataclass
class RescuePlan:
    """Complete rescue plan for a codebase"""
    generated_at: str
    root_path: str
    total_smells: int
    estimated_hours: float
    plans: List[ExtractionPlan] = field(default_factory=list)


# ============================================================================
# PLAN GENERATORS
# ============================================================================

def generate_god_class_plan(finding: Dict[str, Any], root: Path) -> ExtractionPlan:
    """Generate extraction plan for a God Class"""
    file_path = finding['file']
    class_name = finding['name']
    base_name = class_name.lower()

    plan = ExtractionPlan(
        smell_type="god_class",
        smell_location=f"{file_path}:{finding['line']}",
        severity=finding['severity'],
        estimated_minutes=finding['lines'] // 10,  # ~10 lines per minute
        rollback_hint=f"git checkout -- {file_path}",
        test_command=f"pytest -xvs -k {class_name.lower()}"
    )

    # Step 1: Analyze the class
    plan.steps.append(ExtractionStep(
        step_number=1,
        action="ANALYZE",
        description=f"Open {file_path} and identify logical groups of methods in {class_name}",
        source_file=file_path,
        code_hint="""
# Look for methods that:
# 1. Share a common prefix (get_user_*, validate_*, process_*)
# 2. Access the same subset of instance variables
# 3. Are called together in sequence
# 4. Handle the same domain concept (auth, data, ui)
"""
    ))

    # Step 2: Create new module
    dir_path = Path(file_path).parent
    new_module = f"{dir_path}/{base_name}_helpers.py"

    plan.steps.append(ExtractionStep(
        step_number=2,
        action="CREATE",
        description=f"Create new module: {new_module}",
        target_file=new_module,
        code_hint=f'''"""
Helper functions extracted from {class_name}

This module contains extracted helper functions that were previously
methods of the {class_name} class. They are now standalone functions
that accept the necessary data as parameters.
"""
from typing import Any


# Paste extracted functions here
'''
    ))

    # Step 3: Extract helper methods
    plan.steps.append(ExtractionStep(
        step_number=3,
        action="EXTRACT",
        description="Move helper methods (methods that don't use 'self' much) to new module",
        source_file=file_path,
        target_file=new_module,
        code_hint="""
# FOR EACH helper method:
# 1. Copy the method to the new file
# 2. Remove 'self' parameter if not needed
# 3. Add any needed parameters that were self.xxx
# 4. Update imports in new file
# 5. In original class, replace method body with:
#
#    def old_method(self, args):
#        from .class_helpers import old_method
#        return old_method(self.data, args)
"""
    ))

    # Step 4: Run tests
    plan.steps.append(ExtractionStep(
        step_number=4,
        action="TEST",
        description="Run tests to verify extraction didn't break anything",
        code_hint=f"pytest -xvs -k {base_name}"
    ))

    # Step 5: Consider splitting class itself
    plan.steps.append(ExtractionStep(
        step_number=5,
        action="OPTIONAL",
        description="If class is still >200 lines, consider splitting into multiple classes",
        risk_level="MEDIUM",
        code_hint=f"""
# Options:
# 1. {class_name}Core - essential state + core methods
# 2. {class_name}IO - file/network operations
# 3. {class_name}Validator - validation logic
# 4. {class_name}Renderer - display/formatting logic
"""
    ))

    return plan


def generate_god_function_plan(finding: Dict[str, Any], root: Path) -> ExtractionPlan:
    """Generate extraction plan for a God Function"""
    file_path = finding['file']
    func_name = finding['name']

    plan = ExtractionPlan(
        smell_type="god_function",
        smell_location=f"{file_path}:{finding['line']}",
        severity=finding['severity'],
        estimated_minutes=finding['lines'] // 5,
        rollback_hint=f"git checkout -- {file_path}",
        test_command=f"pytest -xvs -k {func_name}"
    )

    # Step 1: Identify blocks
    plan.steps.append(ExtractionStep(
        step_number=1,
        action="ANALYZE",
        description=f"Read {func_name} and mark logical blocks with comments",
        source_file=file_path,
        source_lines=(finding['line'], finding['line'] + finding['lines']),
        code_hint="""
# Add comments like:
# --- BLOCK 1: Input validation ---
# --- BLOCK 2: Data transformation ---
# --- BLOCK 3: Business logic ---
# --- BLOCK 4: Output formatting ---
"""
    ))

    # Step 2: Extract first helper
    plan.steps.append(ExtractionStep(
        step_number=2,
        action="EXTRACT",
        description="Extract the first logical block to a helper function",
        source_file=file_path,
        code_hint=f"""
def _{func_name}_validate_input(args):
    '''Extracted from {func_name}: input validation'''
    # Paste block 1 code here
    # Return validated data

def {func_name}(original_args):
    # Replace block 1 with:
    validated = _{func_name}_validate_input(original_args)
    # ... rest of function
"""
    ))

    # Step 3: Test after first extraction
    plan.steps.append(ExtractionStep(
        step_number=3,
        action="TEST",
        description="Run tests to verify first extraction",
        code_hint="pytest -x"
    ))

    # Step 4: Repeat for remaining blocks
    plan.steps.append(ExtractionStep(
        step_number=4,
        action="REPEAT",
        description="Repeat extraction for each remaining block",
        code_hint="""
# Pattern for each block:
# 1. Create helper: _funcname_blockname(data) -> result
# 2. Move block code to helper
# 3. In main function, call helper
# 4. Test after each extraction

# Final function should look like:
def {func_name}(args):
    validated = _validate_input(args)
    transformed = _transform_data(validated)
    result = _apply_business_logic(transformed)
    return _format_output(result)
"""
    ))

    # Step 5: Consider class extraction
    plan.steps.append(ExtractionStep(
        step_number=5,
        action="OPTIONAL",
        description="If >5 helper functions, consider making a class",
        risk_level="LOW",
        code_hint=f"""
class {func_name.title().replace('_', '')}Processor:
    def __init__(self, config):
        self.config = config

    def validate(self, data): ...
    def transform(self, data): ...
    def process(self, data): ...
    def format(self, result): ...

    def run(self, data):
        '''Main entry point (replaces original function)'''
        validated = self.validate(data)
        transformed = self.transform(validated)
        result = self.process(transformed)
        return self.format(result)
"""
    ))

    return plan


def generate_large_file_plan(finding: Dict[str, Any], root: Path) -> ExtractionPlan:
    """Generate split plan for a large file"""
    file_path = finding['file']
    stem = Path(file_path).stem
    parent = str(Path(file_path).parent)

    plan = ExtractionPlan(
        smell_type="large_file",
        smell_location=file_path,
        severity=finding['severity'],
        estimated_minutes=finding['lines'] // 25,
        rollback_hint=f"git checkout -- {parent}/",
        test_command=f"pytest -xvs {parent}/"
    )

    # Step 1: Create package
    plan.steps.append(ExtractionStep(
        step_number=1,
        action="CREATE",
        description=f"Convert {file_path} to a package (folder)",
        code_hint=f"""
# Run these commands:
mkdir -p {parent}/{stem}
touch {parent}/{stem}/__init__.py

# Or use Python:
from pathlib import Path
pkg = Path('{parent}/{stem}')
pkg.mkdir(exist_ok=True)
(pkg / '__init__.py').touch()
"""
    ))

    # Step 2: Identify domains
    plan.steps.append(ExtractionStep(
        step_number=2,
        action="ANALYZE",
        description="Identify logical domains in the file",
        source_file=file_path,
        code_hint="""
# Common patterns to look for:
# - Classes that work together
# - Functions with common prefixes
# - Imports that cluster together
# - Related constants/configs

# Typical splits:
# - models.py: Data classes, schemas
# - services.py: Business logic
# - utils.py: Helper functions
# - constants.py: Config values
"""
    ))

    # Step 3: Move models
    plan.steps.append(ExtractionStep(
        step_number=3,
        action="MOVE",
        description="Move data models to models.py",
        source_file=file_path,
        target_file=f"{parent}/{stem}/models.py",
        code_hint=f"""
# {parent}/{stem}/models.py
'''Data models extracted from {stem}.py'''

from dataclasses import dataclass
from typing import Optional, List

# Move all @dataclass, TypedDict, NamedTuple here
# Move Pydantic models here
# Move SQLAlchemy models here
"""
    ))

    # Step 4: Move services
    plan.steps.append(ExtractionStep(
        step_number=4,
        action="MOVE",
        description="Move business logic to services.py",
        source_file=file_path,
        target_file=f"{parent}/{stem}/services.py",
        code_hint=f"""
# {parent}/{stem}/services.py
'''Business logic extracted from {stem}.py'''

from .models import *  # Import your models

# Move classes/functions that:
# - Do complex processing
# - Interact with external services
# - Contain business rules
"""
    ))

    # Step 5: Update __init__.py
    plan.steps.append(ExtractionStep(
        step_number=5,
        action="UPDATE",
        description="Re-export public API from __init__.py",
        target_file=f"{parent}/{stem}/__init__.py",
        code_hint=f"""
# {parent}/{stem}/__init__.py
'''
{stem.title().replace('_', ' ')} module

Public API re-exported here for backward compatibility.
'''

from .models import (
    Model1,
    Model2,
)

from .services import (
    process_data,
    validate_input,
)

__all__ = [
    'Model1',
    'Model2',
    'process_data',
    'validate_input',
]
"""
    ))

    # Step 6: Delete original
    plan.steps.append(ExtractionStep(
        step_number=6,
        action="DELETE",
        description=f"Delete original {file_path} (now replaced by package)",
        source_file=file_path,
        risk_level="HIGH",
        code_hint=f"""
# Only after tests pass!
rm {file_path}

# Or safer:
git rm {file_path}
"""
    ))

    return plan


def generate_deep_nesting_plan(finding: Dict[str, Any], root: Path) -> ExtractionPlan:
    """Generate flattening plan for deeply nested code"""
    file_path = finding['file']
    func_name = finding['name']

    plan = ExtractionPlan(
        smell_type="deep_nesting",
        smell_location=f"{file_path}:{finding['line']}",
        severity=finding['severity'],
        estimated_minutes=finding['depth'] * 5,
        rollback_hint=f"git checkout -- {file_path}",
        test_command=f"pytest -xvs -k {func_name}"
    )

    # Step 1: Add guard clauses
    plan.steps.append(ExtractionStep(
        step_number=1,
        action="REFACTOR",
        description="Convert nested conditions to guard clauses",
        source_file=file_path,
        code_hint="""
# BEFORE:
def process(data):
    if data:
        if data.valid:
            if data.ready:
                # actual logic here
                pass

# AFTER:
def process(data):
    if not data:
        return None
    if not data.valid:
        raise ValueError("Invalid data")
    if not data.ready:
        return  # or raise

    # actual logic here - now at top level
"""
    ))

    # Step 2: Extract inner blocks
    plan.steps.append(ExtractionStep(
        step_number=2,
        action="EXTRACT",
        description="Extract deeply nested blocks to helper functions",
        source_file=file_path,
        code_hint=f"""
# BEFORE:
def {func_name}(data):
    for item in data:
        if item.valid:
            for sub in item.subs:
                if sub.ready:
                    # deep logic
                    pass

# AFTER:
def _process_sub(sub):
    '''Extracted inner logic'''
    if not sub.ready:
        return None
    # logic here

def _process_item(item):
    '''Extracted middle logic'''
    if not item.valid:
        return []
    return [_process_sub(sub) for sub in item.subs]

def {func_name}(data):
    results = []
    for item in data:
        results.extend(_process_item(item))
    return results
"""
    ))

    # Step 3: Use comprehensions
    plan.steps.append(ExtractionStep(
        step_number=3,
        action="SIMPLIFY",
        description="Replace simple nested loops with comprehensions",
        code_hint="""
# BEFORE:
results = []
for item in items:
    if item.valid:
        results.append(item.value)

# AFTER:
results = [item.value for item in items if item.valid]
"""
    ))

    return plan


# ============================================================================
# PLAN RUNNER
# ============================================================================

class PlanGenerator:
    """Generates rescue plans from smell findings"""

    def __init__(self, root: Path):
        self.root = root
        self.generators = {
            'god_class': generate_god_class_plan,
            'god_function': generate_god_function_plan,
            'large_file': generate_large_file_plan,
            'deep_nesting': generate_deep_nesting_plan,
        }

    def generate_plan(self, smell_type: str, finding: Dict[str, Any]) -> Optional[ExtractionPlan]:
        """Generate a plan for a single finding"""
        generator = self.generators.get(smell_type)
        if generator:
            return generator(finding, self.root)
        return None

    def generate_rescue_plan(self, all_findings: Dict[str, List[Dict]]) -> RescuePlan:
        """Generate complete rescue plan for all findings"""
        plans = []
        total_minutes = 0

        for smell_type, findings in all_findings.items():
            for finding in findings:
                plan = self.generate_plan(smell_type, finding)
                if plan:
                    plans.append(plan)
                    total_minutes += plan.estimated_minutes

        return RescuePlan(
            generated_at=datetime.now().isoformat(),
            root_path=str(self.root),
            total_smells=sum(len(f) for f in all_findings.values()),
            estimated_hours=total_minutes / 60,
            plans=plans
        )


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def repo_root() -> Path:
    """Get the repository root to scan"""
    current = Path.cwd()
    for marker in ['.git', 'pyproject.toml', 'setup.py', 'src']:
        if (current / marker).exists():
            return current
    if current.name == 'tests':
        return current.parent
    return current


@pytest.fixture
def scan_root(repo_root: Path) -> Path:
    """Get the source directory to scan"""
    for src_dir in ['src', 'lib', 'app', repo_root.name]:
        candidate = repo_root / src_dir
        if candidate.is_dir():
            return candidate
    return repo_root


# ============================================================================
# TESTS
# ============================================================================

class TestExtractionPlanGeneration:
    """Test plan generation for each smell type"""

    def test_generate_full_rescue_plan(self, scan_root: Path, repo_root: Path):
        """Generate complete rescue plan and save to file"""
        # Import detectors from smell detection
        from tests.rescue.test_smell_detection import (
            detect_god_classes,
            detect_god_functions,
            detect_deep_nesting,
            detect_large_files,
        )

        # Detect all smells
        all_findings = {
            'god_class': detect_god_classes(scan_root),
            'god_function': detect_god_functions(scan_root),
            'large_file': detect_large_files(scan_root),
            'deep_nesting': detect_deep_nesting(scan_root),
        }

        # Generate plans
        generator = PlanGenerator(scan_root)
        rescue_plan = generator.generate_rescue_plan(all_findings)

        # Output summary
        print(f"\n{'='*60}")
        print("RESCUE PLAN GENERATED")
        print(f"{'='*60}")
        print(f"Total Smells: {rescue_plan.total_smells}")
        print(f"Estimated Hours: {rescue_plan.estimated_hours:.1f}")
        print(f"Plans Generated: {len(rescue_plan.plans)}")

        # Show first few plans
        for i, plan in enumerate(rescue_plan.plans[:5], 1):
            print(f"\n{'='*60}")
            print(f"PLAN {i}: {plan.smell_type.upper()}")
            print(f"{'='*60}")
            print(f"Location: {plan.smell_location}")
            print(f"Severity: {plan.severity}")
            print(f"Time: ~{plan.estimated_minutes} minutes")
            print(f"\nSteps:")
            for step in plan.steps:
                print(f"  {step.step_number}. [{step.action}] {step.description}")

        # Save plan to file
        output_file = repo_root / "RESCUE_PLAN.json"
        plan_dict = asdict(rescue_plan)
        output_file.write_text(json.dumps(plan_dict, indent=2))
        print(f"\nPlan saved to: {output_file}")

        # Also save markdown version
        md_output = repo_root / "RESCUE_PLAN.md"
        md_content = self._to_markdown(rescue_plan)
        md_output.write_text(md_content)
        print(f"Markdown saved to: {md_output}")

    def _to_markdown(self, plan: RescuePlan) -> str:
        """Convert rescue plan to markdown"""
        lines = [
            "# Rescue Plan",
            "",
            f"Generated: {plan.generated_at}",
            f"Scanned: `{plan.root_path}`",
            "",
            "## Summary",
            "",
            f"- **Total Issues**: {plan.total_smells}",
            f"- **Estimated Effort**: {plan.estimated_hours:.1f} hours",
            f"- **Plans Generated**: {len(plan.plans)}",
            "",
            "---",
            "",
        ]

        for i, p in enumerate(plan.plans, 1):
            lines.extend([
                f"## Plan {i}: {p.smell_type.replace('_', ' ').title()}",
                "",
                f"**Location**: `{p.smell_location}`",
                f"**Severity**: {p.severity}",
                f"**Time**: ~{p.estimated_minutes} minutes",
                "",
                "### Steps",
                "",
            ])

            for step in p.steps:
                lines.append(f"#### Step {step.step_number}: {step.action}")
                lines.append("")
                lines.append(step.description)
                lines.append("")

                if step.source_file:
                    lines.append(f"Source: `{step.source_file}`")
                if step.target_file:
                    lines.append(f"Target: `{step.target_file}`")

                if step.code_hint:
                    lines.extend([
                        "",
                        "```python",
                        step.code_hint.strip(),
                        "```",
                        "",
                    ])

            lines.extend([
                f"**Rollback**: `{p.rollback_hint}`",
                f"**Test**: `{p.test_command}`",
                "",
                "---",
                "",
            ])

        return "\n".join(lines)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
