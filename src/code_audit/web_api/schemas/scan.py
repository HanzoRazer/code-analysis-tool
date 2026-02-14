"""
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
