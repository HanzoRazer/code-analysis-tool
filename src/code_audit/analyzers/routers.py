"""Router density analyzer — detects router sprawl and consolidation targets.

Scans for router/route files, counts endpoints per file, flags duplicates,
classifies routes by usage analytics (when available), and suggests
consolidation phases.

Works with any framework that uses decorator-based routing (FastAPI, Flask,
Django REST, etc.).
"""

from __future__ import annotations

import ast
import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

# ── Thresholds ────────────────────────────────────────────────────────────

_ENDPOINTS_PER_FILE_WARN = 15      # 🟡 many endpoints in one file
_ENDPOINTS_PER_FILE_HIGH = 30      # 🔴 too many
_FILE_LINE_WARN = 500              # large router file
_TOTAL_ROUTES_WARN = 200           # overall route count warning
_TOTAL_ROUTES_HIGH = 400           # overall route count high

# Patterns that indicate a router / route file
_ROUTER_GLOBS = (
    "**/*router*.py",
    "**/routers/**/*.py",
    "**/routes/**/*.py",
)

# HTTP methods recognised as route decorators
_HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "route"})


# ── Data classes ──────────────────────────────────────────────────────────

@dataclass
class RouteEndpoint:
    """A single detected route."""

    path: str
    methods: set[str]
    function_name: str
    file_path: str
    line_number: int
    docstring: str | None
    tags: list[str] = field(default_factory=list)
    call_count: int | None = None
    usage_frequency: float = 0.0


@dataclass
class RouteClassification:
    """Classification of a route into a consolidation category."""

    category: str          # core | power | internal | cull
    confidence: float      # 0.0 – 1.0
    reason: str


@dataclass
class RouterFileInfo:
    """Metadata for a single router file."""

    path: Path
    lines_of_code: int
    endpoints: list[RouteEndpoint] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


# ── Classifier ────────────────────────────────────────────────────────────

_INTERNAL_PATTERNS = (
    "debug", "test", "internal", "dev", "admin",
    "health", "metrics", "status",
)


def classify_route(
    endpoint: RouteEndpoint,
    analytics: dict[str, Any] | None = None,
) -> RouteClassification:
    """Classify a route based on usage analytics and naming heuristics."""
    analytics = analytics or {}
    usage = analytics.get(endpoint.function_name, {})
    frequency = usage.get("frequency", 0)
    call_count = usage.get("call_count", 0)

    # Core — high usage / essential
    if frequency > 0.1 or call_count > 10_000:
        return RouteClassification(
            "core", 0.9,
            f"High usage: {call_count} calls, {frequency:.2%} frequency",
        )

    path_lower = endpoint.path.lower()
    func_lower = endpoint.function_name.lower()

    # Internal utilities
    for pat in _INTERNAL_PATTERNS:
        if pat in path_lower or pat in func_lower:
            return RouteClassification(
                "internal", 0.8,
                f"Internal pattern: {pat}",
            )

    # Power-user routes
    if frequency > 0.01 or "advanced" in path_lower or "expert" in path_lower:
        return RouteClassification(
            "power", 0.7,
            f"Advanced feature with {call_count} calls",
        )

    # Cull candidates — no usage detected
    if call_count == 0 and analytics:
        return RouteClassification(
            "cull", 0.95,
            "No usage detected in analytics",
        )

    return RouteClassification(
        "power", 0.5,
        "Default — needs manual review",
    )


# ── AST helpers ───────────────────────────────────────────────────────────

def _parse_route_decorator(
    decorator: ast.AST,
) -> dict[str, Any] | None:
    """Extract route metadata from a FastAPI/Flask-style decorator."""
    if not isinstance(decorator, ast.Call):
        return None
    if not isinstance(decorator.func, ast.Attribute):
        return None
    if decorator.func.attr not in _HTTP_METHODS:
        return None

    methods = {decorator.func.attr.upper()}
    if decorator.func.attr == "route":
        methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}

    path = "/"
    if decorator.args:
        node = decorator.args[0]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            path = node.value

    tags: list[str] = []
    for kw in decorator.keywords:
        if kw.arg == "tags" and isinstance(kw.value, ast.List):
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    tags.append(elt.value)

    return {"path": path, "methods": methods, "tags": tags}


def _analyze_router_file(
    file_path: Path,
    root: Path,
    analytics: dict[str, Any] | None = None,
) -> RouterFileInfo:
    """Parse a single router file and extract endpoints."""
    content = file_path.read_text(encoding="utf-8", errors="replace")
    lines = content.splitlines()
    info = RouterFileInfo(path=file_path, lines_of_code=len(lines))

    try:
        tree = ast.parse(content, filename=str(file_path))
    except SyntaxError:
        return info

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            info.imports.append(ast.unparse(node))

    analytics = analytics or {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for deco in node.decorator_list:
            route = _parse_route_decorator(deco)
            if not route:
                continue
            usage = analytics.get(node.name, {})
            info.endpoints.append(
                RouteEndpoint(
                    path=route["path"],
                    methods=route["methods"],
                    function_name=node.name,
                    file_path=str(file_path.relative_to(root).as_posix()),
                    line_number=node.lineno,
                    docstring=ast.get_docstring(node),
                    tags=route.get("tags", []),
                    call_count=usage.get("call_count"),
                    usage_frequency=usage.get("frequency", 0),
                )
            )

    return info


# ── Consolidation planner ─────────────────────────────────────────────────

def _find_duplicate_paths(
    endpoint_map: dict[str, list[RouteEndpoint]],
) -> dict[str, list[str]]:
    """Identify routes registered under the same path."""
    return {
        path: [e.file_path for e in eps]
        for path, eps in endpoint_map.items()
        if len(eps) > 1
    }


def build_consolidation_plan(
    routers: dict[Path, RouterFileInfo],
    endpoint_map: dict[str, list[RouteEndpoint]],
    analytics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a phased consolidation plan from scan results."""
    plan: dict[str, list[dict[str, Any]]] = {
        "phase1_cull": [],
        "phase2_merge_duplicates": [],
        "phase3_split_large": [],
        "phase4_domain_consolidation": [],
    }

    # Phase 1 — cull unused routes
    for router in routers.values():
        for ep in router.endpoints:
            cls = classify_route(ep, analytics)
            if cls.category == "cull" and cls.confidence > 0.9:
                plan["phase1_cull"].append({
                    "action": "delete",
                    "file": ep.file_path,
                    "function": ep.function_name,
                    "path": ep.path,
                    "reason": cls.reason,
                })

    # Phase 2 — merge duplicates
    for path, eps in endpoint_map.items():
        if len(eps) > 1:
            plan["phase2_merge_duplicates"].append({
                "action": "merge",
                "path": path,
                "locations": [e.file_path for e in eps],
            })

    # Phase 3 — decompose large files
    for router in routers.values():
        if router.lines_of_code > _FILE_LINE_WARN:
            prefix_groups: dict[str, int] = defaultdict(int)
            for ep in router.endpoints:
                parts = ep.path.strip("/").split("/")
                if parts:
                    prefix_groups[parts[0]] += 1
            plan["phase3_split_large"].append({
                "action": "split",
                "file": str(router.path),
                "lines": router.lines_of_code,
                "suggested_splits": [
                    f"{pfx}_router.py" for pfx, cnt in prefix_groups.items() if cnt >= 3
                ] or ["core_router.py", "admin_router.py"],
            })

    return plan


# ── Analyzer (protocol-conformant) ────────────────────────────────────────

class RoutersAnalyzer:
    """Detects router sprawl, duplicate routes, and consolidation targets.

    Conforms to the ``Analyzer`` protocol: exposes ``id``, ``version``,
    and ``run(root, files) -> list[Finding]``.
    """

    id: str = "routers"
    version: str = "1.0.0"

    def __init__(
        self,
        *,
        endpoints_warn: int = _ENDPOINTS_PER_FILE_WARN,
        endpoints_high: int = _ENDPOINTS_PER_FILE_HIGH,
        total_routes_warn: int = _TOTAL_ROUTES_WARN,
        total_routes_high: int = _TOTAL_ROUTES_HIGH,
        analytics: dict[str, Any] | None = None,
    ):
        self.endpoints_warn = endpoints_warn
        self.endpoints_high = endpoints_high
        self.total_routes_warn = total_routes_warn
        self.total_routes_high = total_routes_high
        self.analytics = analytics

    # ── public API ─────────────────────────────────────────────────

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        """Analyze router files and return findings."""
        findings: list[Finding] = []

        # 1. Discover router files (filter supplied file list)
        router_files = [
            p for p in files
            if p.suffix == ".py" and self._looks_like_router(p, root)
        ]

        # 2. Parse each router file
        routers: dict[Path, RouterFileInfo] = {}
        endpoint_map: dict[str, list[RouteEndpoint]] = defaultdict(list)
        total_endpoints = 0

        for fp in router_files:
            try:
                info = _analyze_router_file(fp, root, self.analytics)
            except (OSError, IOError):
                continue
            routers[fp] = info
            total_endpoints += len(info.endpoints)
            for ep in info.endpoints:
                endpoint_map[ep.path].append(ep)

        # 3. Emit findings

        # 3a. Per-file: too many endpoints
        for fp, info in routers.items():
            n = len(info.endpoints)
            if n < self.endpoints_warn:
                continue
            rel = fp.relative_to(root).as_posix()
            severity = Severity.HIGH if n >= self.endpoints_high else Severity.MEDIUM
            rule_id = "RT-DENSE-001" if n >= self.endpoints_high else "RT-DENSE-002"
            snippet = f"{rel}: {n} endpoints"
            findings.append(Finding(
                finding_id="",
                type=AnalyzerType.ROUTERS,
                severity=severity,
                confidence=1.0,
                message=f"Router file has {n} endpoints (warn: {self.endpoints_warn})",
                location=Location(path=rel, line_start=1, line_end=info.lines_of_code),
                fingerprint=make_fingerprint(rule_id, rel, fp.stem, snippet),
                snippet=snippet,
                metadata={"rule_id": rule_id, "endpoints": n, "lines": info.lines_of_code},
            ))

        # 3b. Duplicate paths
        dups = _find_duplicate_paths(endpoint_map)
        for path, locations in dups.items():
            snippet = f"Duplicate route: {path} in {len(locations)} files"
            findings.append(Finding(
                finding_id="",
                type=AnalyzerType.ROUTERS,
                severity=Severity.HIGH,
                confidence=0.95,
                message=f"Route '{path}' registered in {len(locations)} files: {', '.join(locations)}",
                location=Location(path=locations[0], line_start=1, line_end=1),
                fingerprint=make_fingerprint("RT-DUP-001", path, path, snippet),
                snippet=snippet,
                metadata={"rule_id": "RT-DUP-001", "path": path, "locations": locations},
            ))

        # 3c. Overall route sprawl
        if total_endpoints >= self.total_routes_warn:
            severity = Severity.HIGH if total_endpoints >= self.total_routes_high else Severity.MEDIUM
            rule_id = "RT-SPRAWL-001" if total_endpoints >= self.total_routes_high else "RT-SPRAWL-002"
            snippet = f"Total routes: {total_endpoints}"
            findings.append(Finding(
                finding_id="",
                type=AnalyzerType.ROUTERS,
                severity=severity,
                confidence=1.0,
                message=f"Project has {total_endpoints} total routes (warn: {self.total_routes_warn})",
                location=Location(path=".", line_start=1, line_end=1),
                fingerprint=make_fingerprint(rule_id, ".", "project", snippet),
                snippet=snippet,
                metadata={
                    "rule_id": rule_id,
                    "total_routes": total_endpoints,
                    "router_files": len(routers),
                    "duplicate_paths": len(dups),
                },
            ))

        # 3d. Cull candidates (unused routes from analytics)
        if self.analytics:
            for info in routers.values():
                for ep in info.endpoints:
                    cls = classify_route(ep, self.analytics)
                    if cls.category == "cull" and cls.confidence > 0.9:
                        rel = ep.file_path
                        snippet = f"Unused: {ep.path} ({ep.function_name})"
                        findings.append(Finding(
                            finding_id="",
                            type=AnalyzerType.ROUTERS,
                            severity=Severity.LOW,
                            confidence=cls.confidence,
                            message=f"Route '{ep.path}' ({ep.function_name}) has no recorded usage",
                            location=Location(path=rel, line_start=ep.line_number, line_end=ep.line_number),
                            fingerprint=make_fingerprint("RT-CULL-001", rel, ep.function_name, snippet),
                            snippet=snippet,
                            metadata={
                                "rule_id": "RT-CULL-001",
                                "classification": cls.category,
                                "reason": cls.reason,
                            },
                        ))

        # Assign stable finding IDs
        for i, f in enumerate(findings):
            object.__setattr__(f, "finding_id", f"rt_{f.fingerprint[7:15]}_{i:04d}")

        return findings

    # ── helpers ────────────────────────────────────────────────────

    @staticmethod
    def _looks_like_router(path: Path, root: Path) -> bool:
        """Heuristic: does the filename / path suggest a router file?"""
        rel = str(path.relative_to(root)).lower()
        return any(kw in rel for kw in ("router", "routes", "routers"))


# ── Standalone report generation ──────────────────────────────────────────

def generate_router_report(
    root: Path,
    output_dir: Path | None = None,
    analytics_file: Path | None = None,
) -> dict[str, Any]:
    """Scan router files and produce a JSON + Markdown report.

    Can be invoked directly from ``scripts/`` without the full scan pipeline.
    """
    analytics: dict[str, Any] = {}
    if analytics_file and analytics_file.exists():
        with open(analytics_file) as f:
            analytics = json.load(f)

    # Discover router files
    all_py = list(root.rglob("*.py"))
    router_files = [
        p for p in all_py
        if any(kw in str(p).lower() for kw in ("router", "routes", "routers"))
    ]

    routers: dict[Path, RouterFileInfo] = {}
    endpoint_map: dict[str, list[RouteEndpoint]] = defaultdict(list)

    for fp in router_files:
        try:
            info = _analyze_router_file(fp, root, analytics)
        except (OSError, IOError):
            continue
        routers[fp] = info
        for ep in info.endpoints:
            endpoint_map[ep.path].append(ep)

    # Build classification summary
    classifications: dict[str, list[dict[str, str]]] = {
        "core": [], "power": [], "internal": [], "cull": [],
    }
    for info in routers.values():
        for ep in info.endpoints:
            cls = classify_route(ep, analytics)
            classifications[cls.category].append({
                "path": ep.path,
                "file": ep.file_path,
                "function": ep.function_name,
                "confidence": str(cls.confidence),
            })

    plan = build_consolidation_plan(routers, endpoint_map, analytics)

    total_endpoints = sum(len(r.endpoints) for r in routers.values())
    report = {
        "metrics": {
            "total_files": len(routers),
            "total_endpoints": total_endpoints,
            "files_over_500_lines": len([r for r in routers.values() if r.lines_of_code > 500]),
            "duplicate_paths": len(_find_duplicate_paths(endpoint_map)),
        },
        "classifications": {k: len(v) for k, v in classifications.items()},
        "plan": plan,
    }

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / "router_analysis.json", "w") as f:
            json.dump(report, f, indent=2, default=str)

    return report
