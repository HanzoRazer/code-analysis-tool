"""
TEMPLATE TIER: Migration Validator
===================================
Validates each phase of migration from CLI-only to full SaaS.
Run this to see what's done and what's needed.

Usage:
    pytest tests/template/test_migration_validator.py -v -s
    python tests/template/test_migration_validator.py  # Standalone
"""
import pytest
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import subprocess
import sys
import importlib.util


# ============================================================================
# PHASE DEFINITIONS
# ============================================================================

PHASES = {
    1: {
        "name": "Core API Exists",
        "description": "The core scanning functions exist in api.py",
        "checks": [
            ("api.py exists", "src/code_audit/api.py"),
            ("scan_project function", "function:scan_project"),
            ("governance_audit function", "function:governance_audit"),
            ("detect_debt_patterns function", "function:detect_debt_patterns"),
        ]
    },
    2: {
        "name": "Web API Scaffold (Level 1)",
        "description": "Basic FastAPI structure created",
        "checks": [
            ("web_api package", "src/code_audit/web_api/__init__.py"),
            ("main.py exists", "src/code_audit/web_api/main.py"),
            ("config.py exists", "src/code_audit/web_api/config.py"),
            ("health router", "src/code_audit/web_api/routers/health.py"),
            ("scan router", "src/code_audit/web_api/routers/scan.py"),
            ("scan schema", "src/code_audit/web_api/schemas/scan.py"),
        ]
    },
    3: {
        "name": "API Endpoints Working",
        "description": "Can import and instantiate FastAPI app",
        "checks": [
            ("FastAPI app imports", "import:code_audit.web_api.main:app"),
            ("Health endpoint defined", "endpoint:/health"),
            ("Scan endpoint defined", "endpoint:/scan"),
        ]
    },
    4: {
        "name": "Database Layer (Level 2)",
        "description": "SQLAlchemy models and session management",
        "checks": [
            ("db package", "src/code_audit/web_api/db/__init__.py"),
            ("models.py exists", "src/code_audit/web_api/db/models.py"),
            ("session.py exists", "src/code_audit/web_api/db/session.py"),
            ("User model defined", "model:User"),
            ("ScanJob model defined", "model:ScanJob"),
        ]
    },
    5: {
        "name": "Service Layer (Level 2)",
        "description": "Business logic separated from routes",
        "checks": [
            ("services package", "src/code_audit/web_api/services/__init__.py"),
            ("scan_service.py", "src/code_audit/web_api/services/scan_service.py"),
            ("ScanService class", "class:ScanService"),
        ]
    },
    6: {
        "name": "Authentication (Level 2)",
        "description": "JWT auth and user management",
        "checks": [
            ("deps.py exists", "src/code_audit/web_api/deps.py"),
            ("auth schema", "src/code_audit/web_api/schemas/auth.py"),
            ("get_current_user dependency", "function:get_current_user"),
        ]
    },
    7: {
        "name": "Background Tasks (Level 3)",
        "description": "Celery workers for async processing",
        "checks": [
            ("workers package", "src/code_audit/web_api/workers/__init__.py"),
            ("celery_app.py", "src/code_audit/web_api/workers/celery_app.py"),
            ("tasks.py", "src/code_audit/web_api/workers/tasks.py"),
        ]
    },
    8: {
        "name": "Deployment Ready (Level 3)",
        "description": "Docker and orchestration configs",
        "checks": [
            ("Dockerfile", "Dockerfile"),
            ("docker-compose.yml", "docker-compose.yml"),
        ]
    },
}


# ============================================================================
# CHECK FUNCTIONS
# ============================================================================

def check_file_exists(root: Path, rel_path: str) -> Tuple[bool, str]:
    """Check if a file exists"""
    full_path = root / rel_path
    if full_path.exists():
        return True, f"Found: {rel_path}"
    return False, f"Missing: {rel_path}"


def check_function_exists(root: Path, func_name: str) -> Tuple[bool, str]:
    """Check if a function exists in api.py"""
    api_path = root / "src/code_audit/api.py"
    if not api_path.exists():
        return False, "api.py not found"

    content = api_path.read_text()
    if f"def {func_name}(" in content:
        return True, f"Function {func_name} found"
    return False, f"Function {func_name} not found"


def check_class_exists(root: Path, class_name: str) -> Tuple[bool, str]:
    """Check if a class exists in the codebase"""
    for py_file in (root / "src").rglob("*.py"):
        try:
            content = py_file.read_text()
            if f"class {class_name}(" in content or f"class {class_name}:" in content:
                return True, f"Class {class_name} found in {py_file.name}"
        except Exception:
            continue
    return False, f"Class {class_name} not found"


def check_model_exists(root: Path, model_name: str) -> Tuple[bool, str]:
    """Check if a SQLAlchemy model exists"""
    models_path = root / "src/code_audit/web_api/db/models.py"
    if not models_path.exists():
        return False, "models.py not found"

    content = models_path.read_text()
    if f"class {model_name}(" in content:
        return True, f"Model {model_name} found"
    return False, f"Model {model_name} not found"


def check_import(root: Path, import_path: str) -> Tuple[bool, str]:
    """Check if a module can be imported"""
    # Add src to path temporarily
    src_path = str(root / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    parts = import_path.split(":")
    module_path = parts[0]
    attr_name = parts[1] if len(parts) > 1 else None

    try:
        module = importlib.import_module(module_path)
        if attr_name:
            if hasattr(module, attr_name):
                return True, f"Import OK: {import_path}"
            return False, f"Attribute {attr_name} not found in {module_path}"
        return True, f"Import OK: {module_path}"
    except ImportError as e:
        return False, f"Import failed: {e}"
    except Exception as e:
        return False, f"Error: {e}"


def check_endpoint(root: Path, endpoint: str) -> Tuple[bool, str]:
    """Check if an endpoint is defined in the FastAPI app"""
    # Try to import and inspect the app
    src_path = str(root / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    try:
        from code_audit.web_api.main import app

        # Get all routes
        routes = [route.path for route in app.routes]

        if endpoint in routes:
            return True, f"Endpoint {endpoint} found"

        # Check with prefix
        for route in routes:
            if route.endswith(endpoint) or endpoint in route:
                return True, f"Endpoint {endpoint} found as {route}"

        return False, f"Endpoint {endpoint} not found. Available: {routes[:5]}..."
    except ImportError as e:
        return False, f"Cannot import app: {e}"
    except Exception as e:
        return False, f"Error checking endpoint: {e}"


def run_check(root: Path, check_spec: str) -> Tuple[bool, str]:
    """Run a single check based on its specification"""
    if check_spec.startswith("function:"):
        return check_function_exists(root, check_spec[9:])
    elif check_spec.startswith("class:"):
        return check_class_exists(root, check_spec[6:])
    elif check_spec.startswith("model:"):
        return check_model_exists(root, check_spec[6:])
    elif check_spec.startswith("import:"):
        return check_import(root, check_spec[7:])
    elif check_spec.startswith("endpoint:"):
        return check_endpoint(root, check_spec[9:])
    else:
        return check_file_exists(root, check_spec)


# ============================================================================
# VALIDATION RUNNER
# ============================================================================

class MigrationValidator:
    """Validates migration progress across all phases"""

    def __init__(self, root: Path):
        self.root = root
        self.results: Dict[int, List[Tuple[str, bool, str]]] = {}

    def validate_phase(self, phase_num: int) -> Tuple[int, int]:
        """Validate a single phase, return (passed, total)"""
        if phase_num not in PHASES:
            return 0, 0

        phase = PHASES[phase_num]
        results = []

        for check_name, check_spec in phase["checks"]:
            passed, message = run_check(self.root, check_spec)
            results.append((check_name, passed, message))

        self.results[phase_num] = results

        passed = sum(1 for _, p, _ in results if p)
        total = len(results)
        return passed, total

    def validate_all(self) -> Dict[int, Tuple[int, int]]:
        """Validate all phases"""
        summary = {}
        for phase_num in PHASES:
            summary[phase_num] = self.validate_phase(phase_num)
        return summary

    def get_current_level(self) -> int:
        """Determine current implementation level"""
        summary = self.validate_all()

        # Level 1: Phases 1-3 complete
        if all(summary[p][0] == summary[p][1] for p in [1, 2, 3]):
            # Level 2: Phases 4-6 complete
            if all(summary[p][0] == summary[p][1] for p in [4, 5, 6]):
                # Level 3: Phases 7-8 complete
                if all(summary[p][0] == summary[p][1] for p in [7, 8]):
                    return 3
                return 2
            return 1
        return 0

    def print_report(self):
        """Print a detailed validation report"""
        summary = self.validate_all()

        print("\n" + "=" * 60)
        print("MIGRATION VALIDATION REPORT")
        print("=" * 60)
        print(f"Root: {self.root}")
        print(f"Current Level: {self.get_current_level()}")
        print()

        for phase_num, phase in PHASES.items():
            passed, total = summary[phase_num]
            pct = (passed / total * 100) if total > 0 else 0
            status = "COMPLETE" if passed == total else f"{pct:.0f}%"

            print(f"\nPhase {phase_num}: {phase['name']} [{status}]")
            print(f"  {phase['description']}")
            print(f"  Progress: {passed}/{total}")

            if phase_num in self.results:
                for check_name, check_passed, message in self.results[phase_num]:
                    icon = "OK" if check_passed else "MISSING"
                    print(f"    [{icon}] {check_name}")
                    if not check_passed:
                        print(f"          {message}")

        # Recommendations
        print("\n" + "=" * 60)
        print("NEXT STEPS")
        print("=" * 60)

        current_level = self.get_current_level()

        if current_level == 0:
            print("\n1. Run scaffold to create Level 1 structure:")
            print("   python -m code_audit.scaffold api --level 1")
        elif current_level == 1:
            print("\n1. Level 1 complete! Continue to Level 2:")
            print("   python -m code_audit.scaffold api --level 2")
        elif current_level == 2:
            print("\n1. Level 2 complete! Optional Level 3:")
            print("   python -m code_audit.scaffold api --level 3")
        else:
            print("\nAll levels complete! Ready for deployment.")
            print("1. Configure environment variables")
            print("2. Run: docker-compose up")


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def repo_root() -> Path:
    """Get repository root"""
    current = Path.cwd()
    for marker in ['.git', 'pyproject.toml']:
        if (current / marker).exists():
            return current
    if current.name in ('tests', 'template'):
        return current.parent.parent if current.name == 'template' else current.parent
    return current


@pytest.fixture
def validator(repo_root: Path) -> MigrationValidator:
    """Create a validator instance"""
    return MigrationValidator(repo_root)


# ============================================================================
# TESTS
# ============================================================================

class TestMigrationPhases:
    """Test each migration phase"""

    def test_phase_1_core_api(self, validator: MigrationValidator):
        """Phase 1: Core API functions exist"""
        passed, total = validator.validate_phase(1)
        print(f"\nPhase 1: {passed}/{total} checks passed")

        for name, ok, msg in validator.results[1]:
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {name}: {msg}")

    def test_phase_2_web_scaffold(self, validator: MigrationValidator):
        """Phase 2: Web API scaffold created"""
        passed, total = validator.validate_phase(2)
        print(f"\nPhase 2: {passed}/{total} checks passed")

        for name, ok, msg in validator.results[2]:
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {name}: {msg}")

    def test_phase_3_endpoints(self, validator: MigrationValidator):
        """Phase 3: API endpoints working"""
        passed, total = validator.validate_phase(3)
        print(f"\nPhase 3: {passed}/{total} checks passed")

        for name, ok, msg in validator.results[3]:
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {name}: {msg}")

    def test_phase_4_database(self, validator: MigrationValidator):
        """Phase 4: Database layer (Level 2)"""
        passed, total = validator.validate_phase(4)
        print(f"\nPhase 4: {passed}/{total} checks passed")

        for name, ok, msg in validator.results[4]:
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {name}: {msg}")

    def test_phase_5_services(self, validator: MigrationValidator):
        """Phase 5: Service layer (Level 2)"""
        passed, total = validator.validate_phase(5)
        print(f"\nPhase 5: {passed}/{total} checks passed")

        for name, ok, msg in validator.results[5]:
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {name}: {msg}")

    def test_full_validation_report(self, validator: MigrationValidator):
        """Generate complete validation report"""
        validator.print_report()


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Standalone runner"""
    root = Path.cwd()

    # Find repo root
    for marker in ['.git', 'pyproject.toml']:
        if (root / marker).exists():
            break
        if root.parent != root:
            root = root.parent

    validator = MigrationValidator(root)
    validator.print_report()


if __name__ == "__main__":
    main()
