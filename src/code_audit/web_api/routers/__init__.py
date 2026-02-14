"""
API Routers
===========
Each router handles a specific domain of the API.
"""
from . import health, scan

__all__ = ["health", "scan"]
