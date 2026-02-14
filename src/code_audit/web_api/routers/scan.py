"""
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
        _, result = core_api.scan_project(
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
