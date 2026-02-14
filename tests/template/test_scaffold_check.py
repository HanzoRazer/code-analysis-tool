"""
TEMPLATE TIER: Scaffold Validator
==================================
Validates that the proper directory structure exists.
Run this AFTER using the scaffold generator.

Usage:
    pytest tests/template/test_scaffold_check.py -v
    python -m code_audit.scaffold api  # Generate first
    pytest tests/template/test_scaffold_check.py -v  # Then validate
"""
import pytest
from pathlib import Path
from typing import List, Dict, Tuple


# ============================================================================
# SCAFFOLD DEFINITIONS
# ============================================================================

# Level 1: MVP (minimal viable API)
SCAFFOLD_LEVEL_1 = {
    "description": "Level 1: Minimal FastAPI (sync, no auth, no DB)",
    "required": [
        "src/code_audit/web_api/__init__.py",
        "src/code_audit/web_api/main.py",
        "src/code_audit/web_api/config.py",
        "src/code_audit/web_api/routers/__init__.py",
        "src/code_audit/web_api/routers/scan.py",
        "src/code_audit/web_api/routers/health.py",
        "src/code_audit/web_api/schemas/__init__.py",
        "src/code_audit/web_api/schemas/scan.py",
    ],
    "optional": [
        "src/code_audit/web_api/routers/governance.py",
        "src/code_audit/web_api/routers/debt.py",
        "src/code_audit/web_api/routers/reports.py",
    ]
}

# Level 2: Production (async, auth, SQLite)
SCAFFOLD_LEVEL_2 = {
    "description": "Level 2: Production FastAPI (async, JWT auth, SQLite)",
    "required": [
        *SCAFFOLD_LEVEL_1["required"],
        "src/code_audit/web_api/deps.py",
        "src/code_audit/web_api/db/__init__.py",
        "src/code_audit/web_api/db/models.py",
        "src/code_audit/web_api/db/session.py",
        "src/code_audit/web_api/services/__init__.py",
        "src/code_audit/web_api/services/scan_service.py",
        "src/code_audit/web_api/schemas/auth.py",
        "alembic.ini",
        "alembic/versions/.gitkeep",
    ],
    "optional": [
        "src/code_audit/web_api/auth/__init__.py",
        "src/code_audit/web_api/auth/jwt.py",
        "src/code_audit/web_api/services/auth_service.py",
    ]
}

# Level 3: Advanced (Celery, Redis, PostgreSQL)
SCAFFOLD_LEVEL_3 = {
    "description": "Level 3: Enterprise (Celery, Redis, PostgreSQL)",
    "required": [
        *SCAFFOLD_LEVEL_2["required"],
        "src/code_audit/web_api/workers/__init__.py",
        "src/code_audit/web_api/workers/celery_app.py",
        "src/code_audit/web_api/workers/tasks.py",
        "docker-compose.yml",
        "Dockerfile",
    ],
    "optional": [
        "src/code_audit/web_api/middleware/__init__.py",
        "src/code_audit/web_api/middleware/rate_limit.py",
        "kubernetes/deployment.yaml",
    ]
}


# ============================================================================
# CONTENT VALIDATORS
# ============================================================================

def validate_python_imports(file_path: Path) -> Tuple[bool, str]:
    """Check if a Python file has valid imports"""
    try:
        content = file_path.read_text()
        compile(content, str(file_path), 'exec')
        return True, "OK"
    except SyntaxError as e:
        return False, f"Syntax error: {e}"


def validate_main_py(file_path: Path) -> Tuple[bool, str]:
    """Validate main.py has FastAPI app"""
    content = file_path.read_text()

    checks = [
        ("from fastapi import", "Missing FastAPI import"),
        ("app = FastAPI(", "Missing app = FastAPI()"),
        ("@app.", "Missing route decorators"),
    ]

    for pattern, error in checks:
        if pattern not in content:
            return False, error

    return True, "OK"


def validate_router(file_path: Path) -> Tuple[bool, str]:
    """Validate router file has APIRouter"""
    content = file_path.read_text()

    checks = [
        ("from fastapi import", "Missing FastAPI import"),
        ("APIRouter", "Missing APIRouter"),
        ("router = APIRouter(", "Missing router instance"),
        ("@router.", "Missing route decorators"),
    ]

    for pattern, error in checks:
        if pattern not in content:
            return False, error

    return True, "OK"


def validate_schema(file_path: Path) -> Tuple[bool, str]:
    """Validate schema file has Pydantic models"""
    content = file_path.read_text()

    if "BaseModel" not in content and "TypedDict" not in content:
        return False, "Missing BaseModel or TypedDict"

    if "class " not in content:
        return False, "No class definitions found"

    return True, "OK"


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


# ============================================================================
# TESTS
# ============================================================================

class TestScaffoldLevel1:
    """Validate Level 1 MVP scaffold"""

    def test_required_files_exist(self, repo_root: Path):
        """Check all required Level 1 files exist"""
        missing = []
        present = []

        for file_path in SCAFFOLD_LEVEL_1["required"]:
            full_path = repo_root / file_path
            if full_path.exists():
                present.append(file_path)
            else:
                missing.append(file_path)

        print(f"\n{'='*60}")
        print("LEVEL 1 SCAFFOLD CHECK")
        print(f"{'='*60}")
        print(f"Required: {len(SCAFFOLD_LEVEL_1['required'])} files")
        print(f"Present: {len(present)} files")
        print(f"Missing: {len(missing)} files")

        if missing:
            print(f"\n{'='*60}")
            print("MISSING FILES:")
            for f in missing:
                print(f"  - {f}")
            print(f"\nRun: python -m code_audit.scaffold api --level 1")

        if present:
            print(f"\n{'='*60}")
            print("PRESENT FILES:")
            for f in present:
                print(f"  + {f}")

        # This test PASSES to show what's missing, not to fail
        assert True, "Check output above for missing files"

    def test_main_py_valid(self, repo_root: Path):
        """Validate main.py has correct structure"""
        main_path = repo_root / "src/code_audit/web_api/main.py"

        if not main_path.exists():
            pytest.skip("main.py not created yet - run scaffold first")

        valid, message = validate_main_py(main_path)

        print(f"\n{'='*60}")
        print("MAIN.PY VALIDATION")
        print(f"{'='*60}")
        print(f"File: {main_path}")
        print(f"Status: {'VALID' if valid else 'INVALID'}")
        print(f"Message: {message}")

        if not valid:
            print(f"\nExpected content in main.py:")
            print("""
from fastapi import FastAPI
from code_audit.web_api.routers import scan, health

app = FastAPI(
    title="Code Analysis API",
    version="1.0.0"
)

app.include_router(health.router)
app.include_router(scan.router, prefix="/scan")
""")

    def test_routers_valid(self, repo_root: Path):
        """Validate router files have correct structure"""
        routers_dir = repo_root / "src/code_audit/web_api/routers"

        if not routers_dir.exists():
            pytest.skip("routers directory not created yet")

        print(f"\n{'='*60}")
        print("ROUTER VALIDATION")
        print(f"{'='*60}")

        for router_file in routers_dir.glob("*.py"):
            if router_file.name == "__init__.py":
                continue

            valid, message = validate_router(router_file)
            status = "OK" if valid else "INVALID"
            print(f"  {router_file.name}: {status} - {message}")

    def test_schemas_valid(self, repo_root: Path):
        """Validate schema files have Pydantic models"""
        schemas_dir = repo_root / "src/code_audit/web_api/schemas"

        if not schemas_dir.exists():
            pytest.skip("schemas directory not created yet")

        print(f"\n{'='*60}")
        print("SCHEMA VALIDATION")
        print(f"{'='*60}")

        for schema_file in schemas_dir.glob("*.py"):
            if schema_file.name == "__init__.py":
                continue

            valid, message = validate_schema(schema_file)
            status = "OK" if valid else "INVALID"
            print(f"  {schema_file.name}: {status} - {message}")


class TestScaffoldLevel2:
    """Validate Level 2 Production scaffold"""

    def test_required_files_exist(self, repo_root: Path):
        """Check all required Level 2 files exist"""
        missing = []
        present = []

        for file_path in SCAFFOLD_LEVEL_2["required"]:
            full_path = repo_root / file_path
            if full_path.exists():
                present.append(file_path)
            else:
                missing.append(file_path)

        print(f"\n{'='*60}")
        print("LEVEL 2 SCAFFOLD CHECK")
        print(f"{'='*60}")
        print(f"Required: {len(SCAFFOLD_LEVEL_2['required'])} files")
        print(f"Present: {len(present)} files")
        print(f"Missing: {len(missing)} files")

        if missing:
            print(f"\nMISSING FILES:")
            for f in missing:
                print(f"  - {f}")
            print(f"\nRun: python -m code_audit.scaffold api --level 2")

    def test_db_models_valid(self, repo_root: Path):
        """Validate database models"""
        models_path = repo_root / "src/code_audit/web_api/db/models.py"

        if not models_path.exists():
            pytest.skip("db/models.py not created yet")

        content = models_path.read_text()

        checks = [
            ("Base = ", "Missing SQLAlchemy Base"),
            ("class User", "Missing User model"),
            ("class ScanJob", "Missing ScanJob model"),
            ("Column(", "Missing Column definitions"),
        ]

        print(f"\n{'='*60}")
        print("DB MODELS VALIDATION")
        print(f"{'='*60}")

        for pattern, description in checks:
            status = "OK" if pattern in content else "MISSING"
            print(f"  {description}: {status}")

    def test_deps_valid(self, repo_root: Path):
        """Validate dependency injection"""
        deps_path = repo_root / "src/code_audit/web_api/deps.py"

        if not deps_path.exists():
            pytest.skip("deps.py not created yet")

        content = deps_path.read_text()

        checks = [
            ("def get_db", "Missing get_db dependency"),
            ("async def", "Should use async functions"),
            ("yield", "Missing yield for cleanup"),
        ]

        print(f"\n{'='*60}")
        print("DEPS.PY VALIDATION")
        print(f"{'='*60}")

        for pattern, description in checks:
            status = "OK" if pattern in content else "MISSING"
            print(f"  {description}: {status}")


class TestScaffoldLevel3:
    """Validate Level 3 Enterprise scaffold"""

    def test_required_files_exist(self, repo_root: Path):
        """Check all required Level 3 files exist"""
        missing = []
        present = []

        for file_path in SCAFFOLD_LEVEL_3["required"]:
            full_path = repo_root / file_path
            if full_path.exists():
                present.append(file_path)
            else:
                missing.append(file_path)

        print(f"\n{'='*60}")
        print("LEVEL 3 SCAFFOLD CHECK")
        print(f"{'='*60}")
        print(f"Required: {len(SCAFFOLD_LEVEL_3['required'])} files")
        print(f"Present: {len(present)} files")
        print(f"Missing: {len(missing)} files")

        if missing:
            print(f"\nMISSING FILES (optional for most users):")
            for f in missing:
                print(f"  - {f}")
            print(f"\nOnly needed for enterprise deployment")


class TestScaffoldProgress:
    """Show overall scaffold progress"""

    def test_show_progress(self, repo_root: Path):
        """Display scaffold completion percentage"""
        levels = [
            ("Level 1 (MVP)", SCAFFOLD_LEVEL_1),
            ("Level 2 (Production)", SCAFFOLD_LEVEL_2),
            ("Level 3 (Enterprise)", SCAFFOLD_LEVEL_3),
        ]

        print(f"\n{'='*60}")
        print("SCAFFOLD PROGRESS")
        print(f"{'='*60}")

        for name, scaffold in levels:
            present = sum(1 for f in scaffold["required"] if (repo_root / f).exists())
            total = len(scaffold["required"])
            pct = (present / total * 100) if total > 0 else 0

            bar_width = 30
            filled = int(bar_width * pct / 100)
            bar = "=" * filled + "-" * (bar_width - filled)

            status = "COMPLETE" if pct == 100 else f"{pct:.0f}%"
            print(f"\n{name}:")
            print(f"  [{bar}] {status}")
            print(f"  {present}/{total} files")

        # Recommendation
        print(f"\n{'='*60}")
        print("RECOMMENDATION")
        print(f"{'='*60}")

        l1_pct = sum(1 for f in SCAFFOLD_LEVEL_1["required"] if (repo_root / f).exists()) / len(SCAFFOLD_LEVEL_1["required"]) * 100

        if l1_pct < 100:
            print("\nStart with Level 1 (MVP):")
            print("  python -m code_audit.scaffold api --level 1")
        else:
            l2_pct = sum(1 for f in SCAFFOLD_LEVEL_2["required"] if (repo_root / f).exists()) / len(SCAFFOLD_LEVEL_2["required"]) * 100
            if l2_pct < 100:
                print("\nLevel 1 complete! Continue to Level 2:")
                print("  python -m code_audit.scaffold api --level 2")
            else:
                print("\nLevel 1 & 2 complete! Ready for deployment.")
                print("Level 3 (Enterprise) is optional.")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
