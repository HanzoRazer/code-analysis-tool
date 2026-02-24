#!/usr/bin/env python3
"""
Route Consolidation Tool

Analyzes FastAPI routers to identify unused routes, consolidation opportunities,
and dead code. Designed for luthiers-toolbox Phase 1 remediation (target: <400 routes).

Usage:
    python scripts/route_consolidation_tool.py analyze
    python scripts/route_consolidation_tool.py unused --threshold 0
    python scripts/route_consolidation_tool.py consolidate
    python scripts/route_consolidation_tool.py dead
    python scripts/route_consolidation_tool.py dashboard
    python scripts/route_consolidation_tool.py export --format json

Exit codes:
    0 - Success
    1 - Analysis found issues
    2 - Runtime error
"""

import ast
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from difflib import SequenceMatcher

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    typer = None

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

# ============================================================================
# Configuration
# ============================================================================

# Repo paths (relative to this script)
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent.parent  # code-analysis-tool -> Downloads

# Default target repo (luthiers-toolbox)
DEFAULT_TARGET_REPO = REPO_ROOT / "luthiers-toolbox"
DEFAULT_BACKEND_PATH = "services/api/app"
DEFAULT_FRONTEND_PATH = "packages/client/src"
DEFAULT_MANIFEST_PATH = "router_registry/manifest.py"

# Frontend API call patterns
FRONTEND_API_PATTERNS = [
    # Standard fetch patterns
    r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']',
    r'fetch\s*\(\s*`([^`]+)`',
    # Axios patterns
    r'axios\.(get|post|put|delete|patch)\s*\(\s*[`"\']([^`"\']+)[`"\']',
    r'axios\s*\(\s*\{[^}]*url:\s*[`"\']([^`"\']+)[`"\']',
    # SDK patterns (luthiers-toolbox specific)
    r'apiFetch\s*\(\s*[`"\']([^`"\']+)[`"\']',
    r'apiFetch\s*<[^>]+>\s*\(\s*[`"\']([^`"\']+)[`"\']',
    r'fetchJson\s*\(\s*[`"\']([^`"\']+)[`"\']',
    r'fetchJson\s*<[^>]+>\s*\(\s*[`"\']([^`"\']+)[`"\']',
    # Template literal with interpolation (match base path)
    r'`/api/([^`$]+)',
    r'["\']\/api\/([^"\']+)["\']',
]

# Route methods to detect
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class RouteInfo:
    """Information about a single API route."""
    method: str
    path: str
    full_path: str
    file: Path
    line: int
    function_name: str
    handler_hash: str = ""  # AST hash for similarity detection
    docstring: str = ""
    parameters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "full_path": self.full_path,
            "file": str(self.file),
            "line": self.line,
            "function_name": self.function_name,
            "handler_hash": self.handler_hash,
        }


@dataclass
class RouterSpec:
    """Router specification from manifest."""
    module: str
    prefix: str
    router_attr: str = "router"
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FrontendCall:
    """Frontend API call reference."""
    file: Path
    line: int
    path: str
    method: str = "UNKNOWN"


@dataclass
class ConsolidationSuggestion:
    """A suggestion for route consolidation."""
    strategy: str
    description: str
    routes: List[RouteInfo]
    impact: str
    effort: str
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy": self.strategy,
            "description": self.description,
            "routes": [r.to_dict() for r in self.routes],
            "impact": self.impact,
            "effort": self.effort,
            "confidence": self.confidence,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result."""
    total_routes: int
    total_routers: int
    unused_routes: List[RouteInfo]
    consolidation_suggestions: List[ConsolidationSuggestion]
    dead_routes: List[RouteInfo]
    frontend_calls: List[FrontendCall]
    routes_by_prefix: Dict[str, int]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# Manifest Parser
# ============================================================================

def parse_manifest(manifest_path: Path) -> List[RouterSpec]:
    """Parse router_registry/manifest.py to get all router specs."""
    if not manifest_path.exists():
        print(f"Warning: Manifest not found at {manifest_path}")
        return []

    specs = []
    content = manifest_path.read_text(encoding="utf-8")

    # Pattern matches RouterSpec( ... module="...", prefix="...", ... )
    pattern = r'RouterSpec\s*\(\s*([^)]+)\)'

    for match in re.finditer(pattern, content, re.DOTALL):
        block = match.group(1)

        # Extract module
        module_match = re.search(r'module\s*=\s*["\']([^"\']+)["\']', block)
        if not module_match:
            continue
        module = module_match.group(1)

        # Extract prefix (default to "")
        prefix_match = re.search(r'prefix\s*=\s*["\']([^"\']*)["\']', block)
        prefix = prefix_match.group(1) if prefix_match else ""

        # Extract router_attr (default to "router")
        attr_match = re.search(r'router_attr\s*=\s*["\']([^"\']+)["\']', block)
        router_attr = attr_match.group(1) if attr_match else "router"

        # Check if disabled
        enabled_match = re.search(r'enabled\s*=\s*(True|False)', block)
        enabled = enabled_match.group(1) == "True" if enabled_match else True

        specs.append(RouterSpec(
            module=module,
            prefix=prefix,
            router_attr=router_attr,
            enabled=enabled,
        ))

    return specs


# ============================================================================
# Route Analyzer
# ============================================================================

class RouteUsageAnalyzer:
    """Analyzes backend routes and frontend usage."""

    def __init__(
        self,
        target_repo: Path,
        backend_path: str = DEFAULT_BACKEND_PATH,
        frontend_path: str = DEFAULT_FRONTEND_PATH,
        manifest_path: str = DEFAULT_MANIFEST_PATH,
    ):
        self.target_repo = Path(target_repo)
        self.backend_root = self.target_repo / backend_path
        self.frontend_root = self.target_repo / frontend_path
        self.manifest_path = self.backend_root / manifest_path

        self.routes: List[RouteInfo] = []
        self.frontend_calls: List[FrontendCall] = []
        self.router_specs: List[RouterSpec] = []

    def module_to_path(self, module: str) -> Optional[Path]:
        """Convert module path to file path."""
        if not module.startswith("app."):
            return None

        rel_path = module.replace(".", "/")
        base = self.target_repo / "services" / "api"

        # Try as file
        file_path = base / f"{rel_path}.py"
        if file_path.exists():
            return file_path

        # Try as package (__init__.py)
        init_path = base / rel_path / "__init__.py"
        if init_path.exists():
            return init_path

        return None

    def extract_router_prefix(self, content: str) -> str:
        """Extract internal router prefix from APIRouter() calls."""
        patterns = [
            r'router\s*=\s*APIRouter\s*\([^)]*prefix\s*=\s*["\']([^"\']+)["\']',
            r'APIRouter\s*\(\s*prefix\s*=\s*["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            match = re.search(pattern, content)
            if match:
                return match.group(1)
        return ""

    def compute_handler_hash(self, func: ast.FunctionDef) -> str:
        """Compute a structural hash of a handler function for similarity detection."""
        # Extract key structural elements
        elements = []

        # Parameter names and types
        for arg in func.args.args:
            elements.append(f"arg:{arg.arg}")

        # Return annotation
        if func.returns:
            elements.append(f"returns:{ast.dump(func.returns)}")

        # Body structure (simplified)
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    elements.append(f"call:{node.func.attr}")
                elif isinstance(node.func, ast.Name):
                    elements.append(f"call:{node.func.id}")
            elif isinstance(node, ast.Return):
                elements.append("return")

        return "|".join(elements[:20])  # Truncate for comparison

    def extract_routes_from_file(
        self, file_path: Path, manifest_prefix: str
    ) -> List[RouteInfo]:
        """Extract all route definitions from a Python file."""
        routes = []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return routes

        # Check for internal router prefix
        internal_prefix = self.extract_router_prefix(content)

        if internal_prefix.startswith("/api"):
            prefix = internal_prefix
        elif internal_prefix:
            prefix = manifest_prefix + internal_prefix
        else:
            prefix = manifest_prefix

        # Parse AST
        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            print(f"Warning: Syntax error in {file_path}: {e}")
            return routes

        # Find all decorated functions
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            for decorator in node.decorator_list:
                route_info = self._parse_route_decorator(
                    decorator, node, file_path, prefix
                )
                if route_info:
                    routes.append(route_info)

        return routes

    def _parse_route_decorator(
        self,
        decorator: ast.expr,
        func: ast.FunctionDef,
        file_path: Path,
        prefix: str,
    ) -> Optional[RouteInfo]:
        """Parse a route decorator and extract route info."""

        if isinstance(decorator, ast.Call):
            if isinstance(decorator.func, ast.Attribute):
                attr = decorator.func
                if isinstance(attr.value, ast.Name) and attr.value.id == "router":
                    method = attr.attr.upper()
                    if method in HTTP_METHODS:
                        if decorator.args:
                            arg = decorator.args[0]
                            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                path = arg.value
                                full_path = self._normalize_path(prefix + path)

                                # Get docstring
                                docstring = ast.get_docstring(func) or ""

                                # Get parameters
                                params = [a.arg for a in func.args.args if a.arg != "self"]

                                return RouteInfo(
                                    method=method,
                                    path=path,
                                    full_path=full_path,
                                    file=file_path,
                                    line=decorator.lineno,
                                    function_name=func.name,
                                    handler_hash=self.compute_handler_hash(func),
                                    docstring=docstring[:200] if docstring else "",
                                    parameters=params,
                                )

        return None

    def _normalize_path(self, path: str) -> str:
        """Normalize a path for comparison."""
        path = path.rstrip("/")
        if not path.startswith("/"):
            path = "/" + path
        while "//" in path:
            path = path.replace("//", "/")
        return path

    def scan_backend(self) -> List[RouteInfo]:
        """Scan all backend routers via manifest."""
        self.router_specs = parse_manifest(self.manifest_path)
        all_routes = []

        for spec in self.router_specs:
            if not spec.enabled:
                continue

            file_path = self.module_to_path(spec.module)
            if not file_path:
                continue

            routes = self.extract_routes_from_file(file_path, spec.prefix)
            all_routes.extend(routes)

        self.routes = all_routes
        return all_routes

    def scan_frontend(self) -> List[FrontendCall]:
        """Scan frontend for API calls."""
        calls = []

        if not self.frontend_root.exists():
            print(f"Warning: Frontend root not found: {self.frontend_root}")
            return calls

        # Scan Vue, TS, JS files
        patterns = ["**/*.vue", "**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx"]

        for pattern in patterns:
            for file_path in self.frontend_root.glob(pattern):
                try:
                    content = file_path.read_text(encoding="utf-8")
                except Exception:
                    continue

                for line_num, line in enumerate(content.split("\n"), 1):
                    for api_pattern in FRONTEND_API_PATTERNS:
                        for match in re.finditer(api_pattern, line):
                            path = match.group(1) if match.lastindex else match.group(0)

                            # Normalize path
                            if not path.startswith("/"):
                                path = "/" + path

                            # Infer method from context
                            method = "UNKNOWN"
                            if "axios.get" in line or "GET" in line.upper():
                                method = "GET"
                            elif "axios.post" in line or "POST" in line.upper():
                                method = "POST"
                            elif "axios.put" in line or "PUT" in line.upper():
                                method = "PUT"
                            elif "axios.delete" in line or "DELETE" in line.upper():
                                method = "DELETE"

                            calls.append(FrontendCall(
                                file=file_path,
                                line=line_num,
                                path=path,
                                method=method,
                            ))

        self.frontend_calls = calls
        return calls

    def find_unused_routes(self, threshold: int = 0) -> List[RouteInfo]:
        """Find routes not called from frontend."""
        if not self.routes:
            self.scan_backend()
        if not self.frontend_calls:
            self.scan_frontend()

        # Normalize frontend paths for matching
        frontend_paths = set()
        for call in self.frontend_calls:
            # Remove path parameters for matching
            normalized = re.sub(r'\$\{[^}]+\}', '{param}', call.path)
            normalized = re.sub(r'\{[^}]+\}', '{param}', normalized)
            frontend_paths.add(normalized)

        unused = []
        for route in self.routes:
            # Normalize route path
            normalized = re.sub(r'\{[^}]+\}', '{param}', route.full_path)

            # Check if route is used
            if normalized not in frontend_paths:
                # Also check partial matches
                base_path = normalized.rsplit("/", 1)[0] if "/" in normalized else normalized
                if base_path not in frontend_paths and f"{base_path}/" not in str(frontend_paths):
                    unused.append(route)

        # Filter by threshold (usage count)
        return unused[:] if threshold == 0 else unused


# ============================================================================
# Consolidation Suggester
# ============================================================================

class RouteConsolidationSuggester:
    """Suggests route consolidation opportunities."""

    def __init__(self, routes: List[RouteInfo]):
        self.routes = routes
        self.suggestions: List[ConsolidationSuggestion] = []

    def analyze_all(self) -> List[ConsolidationSuggestion]:
        """Run all consolidation strategies."""
        self.suggestions = []

        self._find_prefix_groups()
        self._find_similar_handlers()
        self._find_crud_sets()
        self._find_version_duplicates()
        self._find_split_routers()

        # Sort by confidence
        self.suggestions.sort(key=lambda s: s.confidence, reverse=True)
        return self.suggestions

    def _find_prefix_groups(self):
        """Find routes that could be grouped under a common prefix."""
        by_prefix: Dict[str, List[RouteInfo]] = defaultdict(list)

        for route in self.routes:
            # Extract 2-level prefix (e.g., /api/rmos)
            parts = route.full_path.split("/")
            if len(parts) >= 3:
                prefix = "/".join(parts[:3])
                by_prefix[prefix].append(route)

        for prefix, routes in by_prefix.items():
            if len(routes) >= 5:
                # Check if routes span multiple files
                files = set(r.file for r in routes)
                if len(files) > 1:
                    self.suggestions.append(ConsolidationSuggestion(
                        strategy="prefix_consolidation",
                        description=f"Consolidate {len(routes)} routes under {prefix} from {len(files)} files",
                        routes=routes,
                        impact=f"Reduce {len(files)} routers to 1",
                        effort="medium",
                        confidence=0.7,
                    ))

    def _find_similar_handlers(self):
        """Find handlers with similar structure (potential duplicates)."""
        by_hash: Dict[str, List[RouteInfo]] = defaultdict(list)

        for route in self.routes:
            if route.handler_hash:
                by_hash[route.handler_hash].append(route)

        for handler_hash, routes in by_hash.items():
            if len(routes) >= 2:
                self.suggestions.append(ConsolidationSuggestion(
                    strategy="duplicate_handlers",
                    description=f"Found {len(routes)} handlers with similar structure",
                    routes=routes,
                    impact=f"Potential {len(routes) - 1} handler deletions",
                    effort="low",
                    confidence=0.6,
                ))

    def _find_crud_sets(self):
        """Find CRUD route sets that could be generated."""
        by_resource: Dict[str, Dict[str, RouteInfo]] = defaultdict(dict)

        for route in self.routes:
            # Extract resource name (e.g., /api/users/{id} -> users)
            parts = route.full_path.split("/")
            if len(parts) >= 3:
                resource = parts[2]
                by_resource[resource][route.method] = route

        for resource, methods in by_resource.items():
            crud_methods = {"GET", "POST", "PUT", "DELETE"}
            if crud_methods.issubset(set(methods.keys())):
                routes = list(methods.values())
                self.suggestions.append(ConsolidationSuggestion(
                    strategy="crud_generation",
                    description=f"Resource '{resource}' has full CRUD - could use generic router",
                    routes=routes,
                    impact="Replace 4+ routes with generic CRUD router",
                    effort="medium",
                    confidence=0.8,
                ))

    def _find_version_duplicates(self):
        """Find routes that exist in multiple versions (v1, v2)."""
        by_base_path: Dict[str, List[RouteInfo]] = defaultdict(list)

        version_pattern = re.compile(r'/v\d+/')

        for route in self.routes:
            base_path = version_pattern.sub("/vX/", route.full_path)
            by_base_path[base_path].append(route)

        for base_path, routes in by_base_path.items():
            if len(routes) >= 2 and "/vX/" in base_path:
                self.suggestions.append(ConsolidationSuggestion(
                    strategy="version_cleanup",
                    description=f"Multiple versions of {base_path.replace('/vX/', '/*/')}",
                    routes=routes,
                    impact=f"Deprecate {len(routes) - 1} old version(s)",
                    effort="low",
                    confidence=0.9,
                ))

    def _find_split_routers(self):
        """Find routers that could be split or merged."""
        by_file: Dict[Path, List[RouteInfo]] = defaultdict(list)

        for route in self.routes:
            by_file[route.file].append(route)

        for file, routes in by_file.items():
            # Large routers (>20 routes) could be split
            if len(routes) > 20:
                self.suggestions.append(ConsolidationSuggestion(
                    strategy="router_split",
                    description=f"{file.name} has {len(routes)} routes - consider splitting",
                    routes=routes,
                    impact="Improve maintainability",
                    effort="high",
                    confidence=0.5,
                ))
            # Tiny routers (<3 routes) could be merged
            elif len(routes) < 3:
                self.suggestions.append(ConsolidationSuggestion(
                    strategy="router_merge",
                    description=f"{file.name} has only {len(routes)} routes - consider merging",
                    routes=routes,
                    impact="Reduce router count",
                    effort="low",
                    confidence=0.6,
                ))


# ============================================================================
# Dead Route Detector
# ============================================================================

class DeadRouteDetector:
    """Detects dead/unreachable routes."""

    def __init__(
        self,
        target_repo: Path,
        router_specs: List[RouterSpec],
        routes: List[RouteInfo],
    ):
        self.target_repo = target_repo
        self.router_specs = router_specs
        self.routes = routes
        self.dead_routes: List[RouteInfo] = []

    def detect_all(self) -> List[RouteInfo]:
        """Run all dead route detection strategies."""
        self.dead_routes = []

        # Check for disabled routers in manifest
        disabled_modules = {
            spec.module for spec in self.router_specs if not spec.enabled
        }

        for route in self.routes:
            # Check if route's module is disabled
            module = self._path_to_module(route.file)
            if module in disabled_modules:
                self.dead_routes.append(route)
                continue

            # Check for commented-out routes (already filtered by AST parsing)
            # Check for routes with "deprecated" in docstring
            if route.docstring and "deprecated" in route.docstring.lower():
                self.dead_routes.append(route)

        return self.dead_routes

    def _path_to_module(self, path: Path) -> str:
        """Convert file path to module path."""
        try:
            rel = path.relative_to(self.target_repo / "services" / "api")
            parts = list(rel.parts)
            if parts[-1].endswith(".py"):
                parts[-1] = parts[-1][:-3]
            return ".".join(parts)
        except ValueError:
            return ""


# ============================================================================
# Main Consolidator
# ============================================================================

class RouteConsolidator:
    """Main orchestrator for route consolidation analysis."""

    def __init__(
        self,
        target_repo: Path = DEFAULT_TARGET_REPO,
        backend_path: str = DEFAULT_BACKEND_PATH,
        frontend_path: str = DEFAULT_FRONTEND_PATH,
    ):
        self.target_repo = Path(target_repo)
        self.backend_path = backend_path
        self.frontend_path = frontend_path

        self.analyzer = RouteUsageAnalyzer(
            target_repo=self.target_repo,
            backend_path=backend_path,
            frontend_path=frontend_path,
        )

        self.result: Optional[AnalysisResult] = None

    def run_full_analysis(self) -> AnalysisResult:
        """Run complete analysis pipeline."""
        print("Scanning backend routes...")
        routes = self.analyzer.scan_backend()
        print(f"  Found {len(routes)} routes in {len(self.analyzer.router_specs)} routers")

        print("Scanning frontend API calls...")
        calls = self.analyzer.scan_frontend()
        print(f"  Found {len(calls)} API calls")

        print("Finding unused routes...")
        unused = self.analyzer.find_unused_routes()
        print(f"  Found {len(unused)} potentially unused routes")

        print("Analyzing consolidation opportunities...")
        suggester = RouteConsolidationSuggester(routes)
        suggestions = suggester.analyze_all()
        print(f"  Found {len(suggestions)} consolidation suggestions")

        print("Detecting dead routes...")
        detector = DeadRouteDetector(
            self.target_repo,
            self.analyzer.router_specs,
            routes,
        )
        dead = detector.detect_all()
        print(f"  Found {len(dead)} dead/deprecated routes")

        # Compute routes by prefix
        by_prefix: Dict[str, int] = defaultdict(int)
        for route in routes:
            parts = route.full_path.split("/")
            if len(parts) >= 3:
                prefix = "/".join(parts[:3])
                by_prefix[prefix] += 1

        self.result = AnalysisResult(
            total_routes=len(routes),
            total_routers=len(self.analyzer.router_specs),
            unused_routes=unused,
            consolidation_suggestions=suggestions,
            dead_routes=dead,
            frontend_calls=calls,
            routes_by_prefix=dict(by_prefix),
        )

        return self.result

    def export_json(self, output_path: Optional[Path] = None) -> str:
        """Export analysis to JSON."""
        if not self.result:
            self.run_full_analysis()

        data = {
            "timestamp": self.result.timestamp,
            "summary": {
                "total_routes": self.result.total_routes,
                "total_routers": self.result.total_routers,
                "unused_routes": len(self.result.unused_routes),
                "dead_routes": len(self.result.dead_routes),
                "consolidation_suggestions": len(self.result.consolidation_suggestions),
            },
            "routes_by_prefix": self.result.routes_by_prefix,
            "unused_routes": [r.to_dict() for r in self.result.unused_routes],
            "dead_routes": [r.to_dict() for r in self.result.dead_routes],
            "consolidation_suggestions": [s.to_dict() for s in self.result.consolidation_suggestions],
        }

        json_str = json.dumps(data, indent=2, default=str)

        if output_path:
            output_path.write_text(json_str, encoding="utf-8")
            print(f"Exported to {output_path}")

        return json_str


# ============================================================================
# CLI Interface
# ============================================================================

def print_table(title: str, headers: List[str], rows: List[List[str]]):
    """Print a formatted table (works with or without Rich)."""
    if HAS_RICH:
        console = Console()
        table = Table(title=title)
        for header in headers:
            table.add_column(header)
        for row in rows:
            table.add_row(*row)
        console.print(table)
    else:
        print(f"\n{title}")
        print("=" * 60)
        print(" | ".join(headers))
        print("-" * 60)
        for row in rows:
            print(" | ".join(row))
        print()


def cmd_analyze(
    target_repo: str = str(DEFAULT_TARGET_REPO),
    backend_path: str = DEFAULT_BACKEND_PATH,
    frontend_path: str = DEFAULT_FRONTEND_PATH,
):
    """Run full route analysis."""
    consolidator = RouteConsolidator(
        target_repo=Path(target_repo),
        backend_path=backend_path,
        frontend_path=frontend_path,
    )

    result = consolidator.run_full_analysis()

    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total routes:         {result.total_routes}")
    print(f"Total routers:        {result.total_routers}")
    print(f"Unused routes:        {len(result.unused_routes)}")
    print(f"Dead routes:          {len(result.dead_routes)}")
    print(f"Consolidation opps:   {len(result.consolidation_suggestions)}")
    print()

    # Top prefixes
    print("Routes by prefix (top 10):")
    sorted_prefixes = sorted(
        result.routes_by_prefix.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    for prefix, count in sorted_prefixes:
        print(f"  {prefix}: {count}")

    return 0


def cmd_unused(
    target_repo: str = str(DEFAULT_TARGET_REPO),
    threshold: int = 0,
):
    """List unused routes."""
    consolidator = RouteConsolidator(target_repo=Path(target_repo))
    consolidator.analyzer.scan_backend()
    consolidator.analyzer.scan_frontend()

    unused = consolidator.analyzer.find_unused_routes(threshold)

    print(f"\nFound {len(unused)} potentially unused routes:\n")

    rows = []
    for route in unused[:50]:  # Limit display
        rel_path = str(route.file).split("app/")[-1] if "app/" in str(route.file) else route.file.name
        rows.append([
            route.method,
            route.full_path[:50],
            rel_path,
            str(route.line),
        ])

    print_table(
        "Unused Routes",
        ["Method", "Path", "File", "Line"],
        rows
    )

    if len(unused) > 50:
        print(f"... and {len(unused) - 50} more")

    return 0


def cmd_consolidate(target_repo: str = str(DEFAULT_TARGET_REPO)):
    """Show consolidation suggestions."""
    consolidator = RouteConsolidator(target_repo=Path(target_repo))
    consolidator.analyzer.scan_backend()

    suggester = RouteConsolidationSuggester(consolidator.analyzer.routes)
    suggestions = suggester.analyze_all()

    print(f"\nFound {len(suggestions)} consolidation opportunities:\n")

    for i, suggestion in enumerate(suggestions[:20], 1):
        print(f"{i}. [{suggestion.strategy}] (confidence: {suggestion.confidence:.0%})")
        print(f"   {suggestion.description}")
        print(f"   Impact: {suggestion.impact}")
        print(f"   Effort: {suggestion.effort}")
        print(f"   Routes: {len(suggestion.routes)}")
        print()

    return 0


def cmd_dead(target_repo: str = str(DEFAULT_TARGET_REPO)):
    """List dead/deprecated routes."""
    consolidator = RouteConsolidator(target_repo=Path(target_repo))
    consolidator.analyzer.scan_backend()

    detector = DeadRouteDetector(
        consolidator.target_repo,
        consolidator.analyzer.router_specs,
        consolidator.analyzer.routes,
    )
    dead = detector.detect_all()

    print(f"\nFound {len(dead)} dead/deprecated routes:\n")

    for route in dead[:30]:
        print(f"  {route.method} {route.full_path}")
        print(f"    File: {route.file.name}:{route.line}")
        if route.docstring:
            print(f"    Note: {route.docstring[:80]}")
        print()

    return 0


def cmd_export(
    target_repo: str = str(DEFAULT_TARGET_REPO),
    output: str = "route_analysis.json",
    format: str = "json",
):
    """Export analysis results."""
    consolidator = RouteConsolidator(target_repo=Path(target_repo))
    consolidator.run_full_analysis()

    output_path = Path(output)

    if format == "json":
        consolidator.export_json(output_path)
    elif format == "yaml" and HAS_YAML:
        # Convert to YAML
        data = json.loads(consolidator.export_json())
        output_path.write_text(yaml.dump(data, default_flow_style=False))
        print(f"Exported to {output_path}")
    else:
        print(f"Unsupported format: {format}")
        return 1

    return 0


def cmd_dashboard(target_repo: str = str(DEFAULT_TARGET_REPO)):
    """Launch interactive dashboard (requires dash/plotly)."""
    try:
        import dash
        from dash import dcc, html
        import plotly.express as px
        import plotly.graph_objects as go
    except ImportError:
        print("Dashboard requires: pip install dash plotly")
        return 1

    consolidator = RouteConsolidator(target_repo=Path(target_repo))
    result = consolidator.run_full_analysis()

    app = dash.Dash(__name__)

    # Create figures
    prefix_data = sorted(
        result.routes_by_prefix.items(),
        key=lambda x: x[1],
        reverse=True
    )[:15]

    fig_prefix = px.bar(
        x=[p[0] for p in prefix_data],
        y=[p[1] for p in prefix_data],
        title="Routes by Prefix",
        labels={"x": "Prefix", "y": "Count"},
    )

    strategy_counts = defaultdict(int)
    for s in result.consolidation_suggestions:
        strategy_counts[s.strategy] += 1

    fig_strategies = px.pie(
        names=list(strategy_counts.keys()),
        values=list(strategy_counts.values()),
        title="Consolidation Strategies",
    )

    app.layout = html.Div([
        html.H1("Route Consolidation Dashboard"),
        html.Div([
            html.Div([
                html.H3("Summary"),
                html.P(f"Total Routes: {result.total_routes}"),
                html.P(f"Total Routers: {result.total_routers}"),
                html.P(f"Unused Routes: {len(result.unused_routes)}"),
                html.P(f"Dead Routes: {len(result.dead_routes)}"),
                html.P(f"Consolidation Opportunities: {len(result.consolidation_suggestions)}"),
            ], style={"width": "30%", "display": "inline-block", "vertical-align": "top"}),
            html.Div([
                dcc.Graph(figure=fig_prefix),
            ], style={"width": "35%", "display": "inline-block"}),
            html.Div([
                dcc.Graph(figure=fig_strategies),
            ], style={"width": "35%", "display": "inline-block"}),
        ]),
    ])

    print("Starting dashboard at http://127.0.0.1:8050")
    app.run_server(debug=True)
    return 0


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nCommands: analyze, unused, consolidate, dead, export, dashboard")
        return 0

    command = sys.argv[1]

    # Parse simple args
    args = {}
    for arg in sys.argv[2:]:
        if arg.startswith("--"):
            if "=" in arg:
                key, value = arg[2:].split("=", 1)
                args[key.replace("-", "_")] = value
            else:
                args[arg[2:].replace("-", "_")] = True

    target = args.get("target_repo", str(DEFAULT_TARGET_REPO))

    if command == "analyze":
        return cmd_analyze(target_repo=target)
    elif command == "unused":
        threshold = int(args.get("threshold", 0))
        return cmd_unused(target_repo=target, threshold=threshold)
    elif command == "consolidate":
        return cmd_consolidate(target_repo=target)
    elif command == "dead":
        return cmd_dead(target_repo=target)
    elif command == "export":
        output = args.get("output", "route_analysis.json")
        fmt = args.get("format", "json")
        return cmd_export(target_repo=target, output=output, format=fmt)
    elif command == "dashboard":
        return cmd_dashboard(target_repo=target)
    else:
        print(f"Unknown command: {command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
