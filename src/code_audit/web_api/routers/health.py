"""
Health Check Router
==================
Endpoints for health checks and readiness probes.
"""
from fastapi import APIRouter

router = APIRouter()

# Version from pyproject.toml
API_VERSION = "0.1.0"


@router.get("/health")
async def health_check():
    """
    Health check endpoint.
    Returns OK if the service is running.
    """
    return {"status": "ok", "version": API_VERSION}


@router.get("/ready")
async def readiness_check():
    """
    Readiness check endpoint.
    Returns OK if the service is ready to handle requests.
    """
    # Add database/external service checks here
    return {"status": "ready"}
