"""
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
