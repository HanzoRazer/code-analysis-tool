"""Lightweight route-analytics middleware for FastAPI.

Captures per-route usage metrics (call count, latency, status codes)
in-memory and exposes them via internal API endpoints.  The exported
JSON is consumable by the ``RoutersAnalyzer`` for data-driven
classification.

Usage::

    from code_audit.utils.route_analytics import RouteAnalyticsMiddleware, analytics_router

    app.add_middleware(RouteAnalyticsMiddleware)
    app.include_router(analytics_router, prefix="/api/_analytics", tags=["internal"])
"""

from __future__ import annotations

import os
import re
import threading
from collections import defaultdict
from datetime import datetime, timezone

try:
    from fastapi import APIRouter
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
except ImportError:  # pragma: no cover — optional dependency
    BaseHTTPMiddleware = object  # type: ignore[assignment,misc]

    class APIRouter:  # type: ignore[no-redef]
        """Stub when FastAPI is not installed."""

        def get(self, *a, **kw):  # noqa: D401
            def _noop(fn):
                return fn
            return _noop

        def post(self, *a, **kw):  # noqa: D401
            def _noop(fn):
                return fn
            return _noop


# ── In-memory stats store ─────────────────────────────────────────────────

_stats: dict = defaultdict(lambda: {
    "call_count": 0,
    "total_ms": 0.0,
    "avg_ms": 0.0,
    "last_used": None,
    "status_codes": defaultdict(int),
})
_lock = threading.Lock()
_start_time = datetime.now(timezone.utc).isoformat()


# ── Middleware ─────────────────────────────────────────────────────────────

_SKIP_PREFIXES = ("/health", "/docs", "/openapi", "/api/_analytics", "/favicon")

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_NUMERIC_ID_RE = re.compile(r"/\d+(?=/|$)")
_HASH_RE = re.compile(r"/[0-9a-f]{32,}(?=/|$)", re.IGNORECASE)


def _normalize_path(path: str) -> str:
    """Replace UUIDs, numeric IDs, and hashes with placeholders."""
    path = _UUID_RE.sub("{id}", path)
    path = _NUMERIC_ID_RE.sub("/{id}", path)
    path = _HASH_RE.sub("/{hash}", path)
    return path


class RouteAnalyticsMiddleware(BaseHTTPMiddleware):
    """Capture per-route usage metrics in memory."""

    async def dispatch(self, request: "Request", call_next):  # type: ignore[override]
        path = request.url.path

        if any(path.startswith(p) for p in _SKIP_PREFIXES):
            return await call_next(request)

        start = datetime.now(timezone.utc)
        response = await call_next(request)
        elapsed_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000

        key = f"{request.method}:{_normalize_path(path)}"

        with _lock:
            _stats[key]["call_count"] += 1
            _stats[key]["total_ms"] += elapsed_ms
            _stats[key]["avg_ms"] = _stats[key]["total_ms"] / _stats[key]["call_count"]
            _stats[key]["last_used"] = datetime.now(timezone.utc).isoformat()
            _stats[key]["status_codes"][str(response.status_code)] += 1

        if os.getenv("ANALYTICS_VERBOSE"):
            print(f"[ROUTE] {key} | {response.status_code} | {elapsed_ms:.1f}ms")

        return response


# ── Analytics API endpoints ───────────────────────────────────────────────

analytics_router = APIRouter()


@analytics_router.get("/summary")
def get_analytics_summary() -> dict:
    """Return route-usage summary (top-20 + bottom-20)."""
    with _lock:
        total_calls = sum(s["call_count"] for s in _stats.values())
        by_usage = sorted(
            [(k, v["call_count"]) for k, v in _stats.items()],
            key=lambda x: -x[1],
        )
        return {
            "collection_started": _start_time,
            "total_routes_hit": len(_stats),
            "total_calls": total_calls,
            "top_20": by_usage[:20],
            "bottom_20_nonzero": [r for r in by_usage if r[1] > 0][-20:],
        }


@analytics_router.get("/export")
def export_analytics() -> dict:
    """Export analytics in a format consumable by ``RoutersAnalyzer``."""
    with _lock:
        total_calls = sum(s["call_count"] for s in _stats.values())
        export: dict[str, dict] = {}
        for key, data in _stats.items():
            method, path = key.split(":", 1)
            func_hint = (
                path.strip("/").replace("/", "_").replace("{", "").replace("}", "")
                or "root"
            )
            freq = data["call_count"] / total_calls if total_calls > 0 else 0
            export[func_hint] = {
                "path": path,
                "method": method,
                "call_count": data["call_count"],
                "frequency": round(freq, 6),
                "avg_response_ms": round(data["avg_ms"], 2),
                "last_used": data["last_used"],
                "status_codes": dict(data["status_codes"]),
            }
        return {
            "collection_started": _start_time,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "routes": export,
        }


@analytics_router.get("/zero-usage")
def get_zero_usage_routes() -> dict:
    """Return routes that were never called (cull candidates)."""
    with _lock:
        zero = [k for k, v in _stats.items() if v["call_count"] == 0]
        return {"zero_usage_routes": zero, "count": len(zero)}


@analytics_router.post("/reset")
def reset_analytics() -> dict:
    """Clear all collected analytics and restart the clock."""
    global _start_time
    with _lock:
        _stats.clear()
        _start_time = datetime.now(timezone.utc).isoformat()
    return {"status": "reset", "new_start_time": _start_time}
