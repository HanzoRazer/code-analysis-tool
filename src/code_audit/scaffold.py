"""
SCAFFOLD GENERATOR
==================
Generates complete, copy-paste ready files for the web API.

Usage:
    python -m code_audit.scaffold api --level 1    # MVP
    python -m code_audit.scaffold api --level 2    # Production
    python -m code_audit.scaffold api --level 3    # Enterprise
"""
import argparse
from pathlib import Path
from typing import Dict
import sys


# ============================================================================
# FILE TEMPLATES - Complete, working code
# ============================================================================

# -----------------------------------------------------------------------------
# Level 1: MVP Files
# -----------------------------------------------------------------------------

TEMPLATE_WEB_API_INIT = '''"""
Code Audit Web API
==================
FastAPI-based REST API for code analysis.

Quick Start:
    uvicorn code_audit.web_api.main:app --reload
"""
from .main import app

__all__ = ["app"]
'''

TEMPLATE_CONFIG = '''"""
Configuration settings for the API.
Environment variables override defaults.
"""
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class Settings:
    """API Configuration"""

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # CORS
    CORS_ORIGINS: List[str] = field(default_factory=lambda: ["*"])

    # Rate limiting (Level 2+)
    RATE_LIMIT_ENABLED: bool = False
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds

    # Database (Level 2+)
    DATABASE_URL: str = "sqlite:///./code_audit.db"
    DB_ECHO: bool = False

    # Redis (Level 3)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Auth (Level 2+)
    SECRET_KEY: str = "change-me-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    def __post_init__(self):
        """Load from environment variables"""
        for key in self.__dataclass_fields__:
            env_value = os.getenv(key)
            if env_value is not None:
                field_type = self.__dataclass_fields__[key].type
                if field_type == bool:
                    setattr(self, key, env_value.lower() in ("true", "1", "yes"))
                elif field_type == int:
                    setattr(self, key, int(env_value))
                elif field_type == List[str]:
                    setattr(self, key, env_value.split(","))
                else:
                    setattr(self, key, env_value)


# Global settings instance
settings = Settings()
'''

TEMPLATE_MAIN = '''"""
FastAPI Application
==================
Main entry point for the Code Audit API.

Run with:
    uvicorn code_audit.web_api.main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from code_audit.web_api.config import settings
from code_audit.web_api.routers import health, scan

# Create application
app = FastAPI(
    title="Code Analysis API",
    description="Multi-language code analysis and governance platform",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, tags=["Health"])
app.include_router(scan.router, prefix="/scan", tags=["Scan"])


@app.get("/")
async def root():
    """Root endpoint - API info"""
    return {
        "name": "Code Analysis API",
        "version": "1.0.0",
        "docs": "/docs" if settings.DEBUG else "disabled",
    }


# For running directly: python -m code_audit.web_api.main
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
'''

TEMPLATE_ROUTERS_INIT = '''"""
API Routers
===========
Each router handles a specific domain of the API.
"""
from . import health, scan

__all__ = ["health", "scan"]
'''

TEMPLATE_HEALTH_ROUTER = '''"""
Health Check Router
==================
Endpoints for health checks and readiness probes.
"""
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    """
    Health check endpoint.
    Returns OK if the service is running.
    """
    return {"status": "ok"}


@router.get("/ready")
async def readiness_check():
    """
    Readiness check endpoint.
    Returns OK if the service is ready to handle requests.
    """
    # Add database/external service checks here
    return {"status": "ready"}
'''

TEMPLATE_SCAN_ROUTER = '''"""
Scan Router
===========
Endpoints for running code scans.
"""
from fastapi import APIRouter, HTTPException
from pathlib import Path
import tempfile
import shutil

from code_audit.web_api.schemas.scan import (
    ScanRequest,
    ScanResponse,
    ScanSummary,
)
from code_audit import api as core_api

router = APIRouter()


@router.post("/", response_model=ScanResponse)
async def run_scan(request: ScanRequest):
    """
    Run a code scan on a repository.

    - **repo_path**: Local path to scan (for MVP)
    - **branch**: Git branch (default: main)
    - **project_id**: Optional project identifier
    """
    # Validate path exists
    target = Path(request.repo_path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {request.repo_path}")

    # Run the scan using core API
    try:
        result = core_api.scan_project(
            root=target,
            project_id=request.project_id or "",
            ci_mode=False,
        )

        # Transform to response
        summary = result.get("summary", {})
        return ScanResponse(
            status="complete",
            project_id=request.project_id,
            summary=ScanSummary(
                files_scanned=summary.get("files_scanned", 0),
                total_lines=summary.get("total_lines", 0),
                issues_found=summary.get("total_findings", 0),
                confidence_score=summary.get("confidence_score", 0),
            ),
            result=result,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/governance")
async def run_governance_audit(request: ScanRequest):
    """
    Run governance checks on a repository.
    """
    target = Path(request.repo_path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {request.repo_path}")

    try:
        # Use governance audit from core API
        result = core_api.governance_audit(
            root=target,
            gates=["deprecation", "import_ban", "legacy_usage", "sdk_boundary"],
        )
        return {"status": "complete", "gates": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/debt")
async def analyze_debt(request: ScanRequest):
    """
    Analyze technical debt in a repository.
    """
    target = Path(request.repo_path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {request.repo_path}")

    try:
        result = core_api.detect_debt_patterns(root=target)
        return {"status": "complete", "debt": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
'''

TEMPLATE_SCHEMAS_INIT = '''"""
Pydantic Schemas
===============
Request and response models for the API.
"""
from .scan import ScanRequest, ScanResponse, ScanSummary

__all__ = ["ScanRequest", "ScanResponse", "ScanSummary"]
'''

TEMPLATE_SCAN_SCHEMA = '''"""
Scan Schemas
============
Request and response models for scan endpoints.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class ScanRequest(BaseModel):
    """Request to run a code scan"""

    repo_path: str = Field(..., description="Local path to the repository")
    branch: str = Field(default="main", description="Git branch to scan")
    project_id: Optional[str] = Field(default=None, description="Project identifier")

    class Config:
        json_schema_extra = {
            "example": {
                "repo_path": "/path/to/repo",
                "branch": "main",
                "project_id": "my-project"
            }
        }


class ScanSummary(BaseModel):
    """Summary of scan results"""

    files_scanned: int = Field(default=0)
    total_lines: int = Field(default=0)
    issues_found: int = Field(default=0)
    confidence_score: float = Field(default=0.0)


class ScanResponse(BaseModel):
    """Response from a scan operation"""

    status: str = Field(..., description="Scan status: pending, complete, failed")
    project_id: Optional[str] = Field(default=None)
    summary: ScanSummary
    result: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "status": "complete",
                "project_id": "my-project",
                "summary": {
                    "files_scanned": 42,
                    "total_lines": 5000,
                    "issues_found": 7,
                    "confidence_score": 85.5
                },
                "result": {}
            }
        }
'''

# -----------------------------------------------------------------------------
# Level 2: Production Files (adds to Level 1)
# -----------------------------------------------------------------------------

TEMPLATE_DEPS = '''"""
Dependency Injection
====================
FastAPI dependencies for database, auth, etc.
"""
from typing import AsyncGenerator
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError, jwt

from code_audit.web_api.config import settings
from code_audit.web_api.db.session import async_session_maker
from code_audit.web_api.db.models import User


# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token", auto_error=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Database session dependency.
    Yields a session and ensures cleanup.
    """
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_current_user_optional(
    token: str | None = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """
    Get current user if authenticated, None otherwise.
    Use for endpoints that work with or without auth.
    """
    if token is None:
        return None

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None

    # Fetch user from database
    user = await db.get(User, user_id)
    return user


async def get_current_user(
    user: User | None = Depends(get_current_user_optional),
) -> User:
    """
    Get current user - requires authentication.
    Raises 401 if not authenticated.
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
'''

TEMPLATE_DB_INIT = '''"""
Database Package
================
SQLAlchemy models and session management.
"""
from .models import Base, User, ScanJob
from .session import engine, async_session_maker

__all__ = ["Base", "User", "ScanJob", "engine", "async_session_maker"]
'''

TEMPLATE_DB_MODELS = '''"""
Database Models
===============
SQLAlchemy ORM models.
"""
from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import Column, String, DateTime, Integer, Float, Text, Boolean, JSON, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    """Base class for all models"""
    pass


def generate_uuid() -> str:
    """Generate a UUID string"""
    return str(uuid.uuid4())


class UserRole(enum.Enum):
    """User role enum"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


class ScanStatus(enum.Enum):
    """Scan job status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class User(Base):
    """User model"""
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=generate_uuid)
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    role = Column(SQLEnum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = relationship("ScanJob", back_populates="user")

    def __repr__(self):
        return f"<User {self.username}>"


class ScanJob(Base):
    """Scan job model"""
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=generate_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    project_id = Column(String, nullable=True, index=True)
    repo_path = Column(String, nullable=False)
    branch = Column(String, default="main")
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)

    # Timing
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    # Results
    summary = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)

    # Metrics
    files_scanned = Column(Integer, default=0)
    total_lines = Column(Integer, default=0)
    issues_found = Column(Integer, default=0)
    confidence_score = Column(Float, default=0.0)

    # Relationships
    user = relationship("User", back_populates="scans")

    def __repr__(self):
        return f"<ScanJob {self.id} ({self.status.value})>"
'''

TEMPLATE_DB_SESSION = '''"""
Database Session
================
Async SQLAlchemy session factory.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from code_audit.web_api.config import settings


# Convert sqlite:/// to sqlite+aiosqlite:///
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite:///"):
    db_url = db_url.replace("sqlite:///", "sqlite+aiosqlite:///")

# Create async engine
engine = create_async_engine(
    db_url,
    echo=settings.DB_ECHO,
    future=True,
)

# Session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db():
    """Initialize database tables"""
    from code_audit.web_api.db.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
'''

TEMPLATE_SERVICES_INIT = '''"""
Service Layer
=============
Business logic services.
"""
from .scan_service import ScanService

__all__ = ["ScanService"]
'''

TEMPLATE_SCAN_SERVICE = '''"""
Scan Service
============
Business logic for code scanning.
"""
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import asyncio
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.ext.asyncio import AsyncSession

from code_audit.web_api.db.models import ScanJob, ScanStatus
from code_audit.web_api.schemas.scan import ScanRequest
from code_audit import api as core_api


# Thread pool for running sync scan operations
_executor = ThreadPoolExecutor(max_workers=4)


class ScanService:
    """Service for managing scan operations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_job(self, request: ScanRequest, user_id: Optional[str] = None) -> ScanJob:
        """Create a new scan job"""
        job = ScanJob(
            user_id=user_id,
            project_id=request.project_id,
            repo_path=request.repo_path,
            branch=request.branch,
            status=ScanStatus.PENDING,
        )
        self.db.add(job)
        await self.db.commit()
        await self.db.refresh(job)
        return job

    async def run_scan(self, job: ScanJob) -> ScanJob:
        """Execute a scan job"""
        # Update status to running
        job.status = ScanStatus.RUNNING
        job.started_at = datetime.utcnow()
        await self.db.commit()

        try:
            # Run sync scan in thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                _executor,
                self._run_sync_scan,
                job.repo_path,
                job.project_id,
            )

            # Update with results
            job.status = ScanStatus.COMPLETE
            job.completed_at = datetime.utcnow()
            job.duration_seconds = (job.completed_at - job.started_at).total_seconds()
            job.result = result
            job.summary = result.get("summary", {})
            job.files_scanned = job.summary.get("files_scanned", 0)
            job.total_lines = job.summary.get("total_lines", 0)
            job.issues_found = job.summary.get("total_findings", 0)
            job.confidence_score = job.summary.get("confidence_score", 0.0)

        except Exception as e:
            job.status = ScanStatus.FAILED
            job.completed_at = datetime.utcnow()
            job.error_message = str(e)

        await self.db.commit()
        return job

    def _run_sync_scan(self, repo_path: str, project_id: Optional[str]) -> Dict[str, Any]:
        """Run synchronous scan (called from thread pool)"""
        return core_api.scan_project(
            root=Path(repo_path),
            project_id=project_id or "",
            ci_mode=False,
        )

    async def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Get a scan job by ID"""
        return await self.db.get(ScanJob, job_id)

    async def get_jobs(
        self,
        user_id: Optional[str] = None,
        project_id: Optional[str] = None,
        limit: int = 20,
    ) -> list[ScanJob]:
        """Get scan jobs with optional filters"""
        from sqlalchemy import select

        query = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)

        if user_id:
            query = query.where(ScanJob.user_id == user_id)
        if project_id:
            query = query.where(ScanJob.project_id == project_id)

        result = await self.db.execute(query)
        return list(result.scalars().all())
'''

TEMPLATE_AUTH_SCHEMA = '''"""
Auth Schemas
============
Request and response models for authentication.
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional


class UserCreate(BaseModel):
    """Schema for creating a new user"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None


class UserResponse(BaseModel):
    """Schema for user responses"""
    id: str
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    """OAuth2 token response"""
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Data encoded in JWT token"""
    sub: str  # User ID
    exp: int  # Expiration timestamp
'''

# -----------------------------------------------------------------------------
# Level 3: Enterprise Files (adds to Level 2)
# -----------------------------------------------------------------------------

TEMPLATE_WORKERS_INIT = '''"""
Background Workers
==================
Celery tasks for async job processing.
"""
from .celery_app import celery_app
from .tasks import run_scan_task

__all__ = ["celery_app", "run_scan_task"]
'''

TEMPLATE_CELERY_APP = '''"""
Celery Application
==================
Background task queue configuration.
"""
from celery import Celery

from code_audit.web_api.config import settings


celery_app = Celery(
    "code_audit",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["code_audit.web_api.workers.tasks"],
)

# Configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour
    worker_prefetch_multiplier=1,
)
'''

TEMPLATE_CELERY_TASKS = '''"""
Celery Tasks
============
Background task definitions.
"""
from datetime import datetime
from pathlib import Path

from code_audit.web_api.workers.celery_app import celery_app
from code_audit import api as core_api


@celery_app.task(bind=True, name="run_scan_task")
def run_scan_task(self, job_id: str, repo_path: str, project_id: str = ""):
    """
    Run a code scan as a background task.

    Args:
        job_id: Database ID of the ScanJob
        repo_path: Path to the repository
        project_id: Optional project identifier

    Returns:
        Scan result dictionary
    """
    # Update task state
    self.update_state(state="PROGRESS", meta={"status": "scanning"})

    try:
        # Run the scan
        result = core_api.scan_project(
            root=Path(repo_path),
            project_id=project_id,
            ci_mode=False,
        )

        return {
            "status": "complete",
            "job_id": job_id,
            "result": result,
        }

    except Exception as e:
        return {
            "status": "failed",
            "job_id": job_id,
            "error": str(e),
        }
'''

TEMPLATE_DOCKER_COMPOSE = '''version: "3.8"

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/code_audit
      - REDIS_URL=redis://redis:6379/0
      - DEBUG=true
    depends_on:
      - db
      - redis
    volumes:
      - .:/app

  worker:
    build: .
    command: celery -A code_audit.web_api.workers.celery_app worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/code_audit
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=code_audit
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
'''

TEMPLATE_DOCKERFILE = '''FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Install package
RUN pip install -e .

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "code_audit.web_api.main:app", "--host", "0.0.0.0", "--port", "8000"]
'''


# ============================================================================
# FILE REGISTRY
# ============================================================================

LEVEL_1_FILES = {
    "src/code_audit/web_api/__init__.py": TEMPLATE_WEB_API_INIT,
    "src/code_audit/web_api/config.py": TEMPLATE_CONFIG,
    "src/code_audit/web_api/main.py": TEMPLATE_MAIN,
    "src/code_audit/web_api/routers/__init__.py": TEMPLATE_ROUTERS_INIT,
    "src/code_audit/web_api/routers/health.py": TEMPLATE_HEALTH_ROUTER,
    "src/code_audit/web_api/routers/scan.py": TEMPLATE_SCAN_ROUTER,
    "src/code_audit/web_api/schemas/__init__.py": TEMPLATE_SCHEMAS_INIT,
    "src/code_audit/web_api/schemas/scan.py": TEMPLATE_SCAN_SCHEMA,
}

LEVEL_2_FILES = {
    **LEVEL_1_FILES,
    "src/code_audit/web_api/deps.py": TEMPLATE_DEPS,
    "src/code_audit/web_api/db/__init__.py": TEMPLATE_DB_INIT,
    "src/code_audit/web_api/db/models.py": TEMPLATE_DB_MODELS,
    "src/code_audit/web_api/db/session.py": TEMPLATE_DB_SESSION,
    "src/code_audit/web_api/services/__init__.py": TEMPLATE_SERVICES_INIT,
    "src/code_audit/web_api/services/scan_service.py": TEMPLATE_SCAN_SERVICE,
    "src/code_audit/web_api/schemas/auth.py": TEMPLATE_AUTH_SCHEMA,
}

LEVEL_3_FILES = {
    **LEVEL_2_FILES,
    "src/code_audit/web_api/workers/__init__.py": TEMPLATE_WORKERS_INIT,
    "src/code_audit/web_api/workers/celery_app.py": TEMPLATE_CELERY_APP,
    "src/code_audit/web_api/workers/tasks.py": TEMPLATE_CELERY_TASKS,
    "docker-compose.yml": TEMPLATE_DOCKER_COMPOSE,
    "Dockerfile": TEMPLATE_DOCKERFILE,
}


# ============================================================================
# SCAFFOLD GENERATOR
# ============================================================================

def scaffold_api(root: Path, level: int = 1, force: bool = False) -> Dict[str, str]:
    """
    Generate API scaffold files.

    Args:
        root: Repository root directory
        level: Scaffold level (1=MVP, 2=Production, 3=Enterprise)
        force: Overwrite existing files

    Returns:
        Dictionary of created files and their status
    """
    results = {}

    # Select file set based on level
    if level == 1:
        files = LEVEL_1_FILES
    elif level == 2:
        files = LEVEL_2_FILES
    else:
        files = LEVEL_3_FILES

    for file_path, content in files.items():
        full_path = root / file_path

        # Check if exists
        if full_path.exists() and not force:
            results[file_path] = "SKIPPED (exists)"
            continue

        # Create parent directories
        full_path.parent.mkdir(parents=True, exist_ok=True)

        # Write file
        full_path.write_text(content.lstrip())
        results[file_path] = "CREATED"

    return results


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Generate API scaffold")
    parser.add_argument("target", choices=["api"], help="What to scaffold")
    parser.add_argument("--level", type=int, default=1, choices=[1, 2, 3],
                        help="Scaffold level: 1=MVP, 2=Production, 3=Enterprise")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root")

    args = parser.parse_args()

    print(f"Scaffolding Level {args.level} API...")
    print(f"Root: {args.root}")
    print()

    results = scaffold_api(args.root, args.level, args.force)

    for file_path, status in results.items():
        icon = "+" if status == "CREATED" else "-"
        print(f"  [{icon}] {file_path}: {status}")

    created = sum(1 for s in results.values() if s == "CREATED")
    skipped = sum(1 for s in results.values() if "SKIPPED" in s)

    print()
    print(f"Created: {created} files")
    print(f"Skipped: {skipped} files")
    print()
    print("Next steps:")
    print("  1. pip install fastapi uvicorn sqlalchemy aiosqlite pydantic")
    print("  2. uvicorn code_audit.web_api.main:app --reload")
    print("  3. Open http://localhost:8000/docs")


if __name__ == "__main__":
    main()
