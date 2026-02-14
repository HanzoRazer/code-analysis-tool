"""
Code Audit Web API
==================
FastAPI-based REST API for code analysis.

Quick Start:
    uvicorn code_audit.web_api.main:app --reload
"""
from .main import app

__all__ = ["app"]
