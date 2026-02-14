"""Tests for the RoutersAnalyzer and supporting helpers."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from code_audit.analyzers.routers import (
    RoutersAnalyzer,
    RouteEndpoint,
    RouterFileInfo,
    classify_route,
    _analyze_router_file,
    _find_duplicate_paths,
    build_consolidation_plan,
    generate_router_report,
)
from code_audit.model import AnalyzerType, Severity


# ── Fixtures ──────────────────────────────────────────────────────────────

SIMPLE_ROUTER = textwrap.dedent("""\
    from fastapi import APIRouter

    router = APIRouter()

    @router.get("/items")
    def list_items():
        return []

    @router.post("/items")
    def create_item():
        return {}

    @router.get("/items/{item_id}")
    def get_item(item_id: str):
        return {}
""")

DENSE_ROUTER = textwrap.dedent("""\
    from fastapi import APIRouter

    router = APIRouter()
""") + "\n".join(
    f'@router.get("/ep{i}")\ndef endpoint_{i}():\n    return {i}\n'
    for i in range(20)
)


@pytest.fixture()
def router_tree(tmp_path: Path) -> Path:
    """Create a minimal router directory structure."""
    routers = tmp_path / "app" / "routers"
    routers.mkdir(parents=True)

    (routers / "items_router.py").write_text(SIMPLE_ROUTER, encoding="utf-8")
    (routers / "dense_router.py").write_text(DENSE_ROUTER, encoding="utf-8")

    # A duplicate path in a second file
    dup = textwrap.dedent("""\
        from fastapi import APIRouter
        router = APIRouter()

        @router.get("/items")
        def list_items_v2():
            return []
    """)
    (routers / "items_v2_router.py").write_text(dup, encoding="utf-8")

    # A non-router Python file (should be ignored)
    (tmp_path / "app" / "models.py").write_text("class Item: ...\n", encoding="utf-8")

    return tmp_path / "app"


# ── classify_route ────────────────────────────────────────────────────────

class TestClassifyRoute:
    def _ep(self, name: str = "my_func", path: str = "/") -> RouteEndpoint:
        return RouteEndpoint(
            path=path, methods={"GET"}, function_name=name,
            file_path="router.py", line_number=1, docstring=None,
        )

    def test_core_by_call_count(self):
        analytics = {"my_func": {"call_count": 50_000, "frequency": 0.2}}
        cls = classify_route(self._ep(), analytics)
        assert cls.category == "core"
        assert cls.confidence >= 0.8

    def test_internal_pattern(self):
        cls = classify_route(self._ep(name="debug_state", path="/debug/state"))
        assert cls.category == "internal"

    def test_cull_no_usage(self):
        analytics = {"my_func": {"call_count": 0, "frequency": 0}}
        cls = classify_route(self._ep(), analytics)
        assert cls.category == "cull"

    def test_power_default(self):
        cls = classify_route(self._ep())
        assert cls.category == "power"
        assert cls.confidence <= 0.6

    def test_internal_health(self):
        cls = classify_route(self._ep(name="healthcheck", path="/health"))
        assert cls.category == "internal"


# ── _analyze_router_file ──────────────────────────────────────────────────

class TestAnalyzeRouterFile:
    def test_extracts_endpoints(self, tmp_path: Path):
        f = tmp_path / "router.py"
        f.write_text(SIMPLE_ROUTER, encoding="utf-8")
        info = _analyze_router_file(f, tmp_path)
        assert len(info.endpoints) == 3
        names = {e.function_name for e in info.endpoints}
        assert names == {"list_items", "create_item", "get_item"}

    def test_extracts_methods(self, tmp_path: Path):
        f = tmp_path / "router.py"
        f.write_text(SIMPLE_ROUTER, encoding="utf-8")
        info = _analyze_router_file(f, tmp_path)
        gets = [e for e in info.endpoints if "GET" in e.methods]
        posts = [e for e in info.endpoints if "POST" in e.methods]
        assert len(gets) == 2
        assert len(posts) == 1

    def test_counts_lines(self, tmp_path: Path):
        f = tmp_path / "router.py"
        f.write_text(SIMPLE_ROUTER, encoding="utf-8")
        info = _analyze_router_file(f, tmp_path)
        assert info.lines_of_code > 5

    def test_handles_syntax_error(self, tmp_path: Path):
        f = tmp_path / "bad_router.py"
        f.write_text("def oops(:\n  pass", encoding="utf-8")
        info = _analyze_router_file(f, tmp_path)
        assert info.endpoints == []

    def test_injects_analytics(self, tmp_path: Path):
        f = tmp_path / "router.py"
        f.write_text(SIMPLE_ROUTER, encoding="utf-8")
        analytics = {"list_items": {"call_count": 1000, "frequency": 0.5}}
        info = _analyze_router_file(f, tmp_path, analytics)
        ep = next(e for e in info.endpoints if e.function_name == "list_items")
        assert ep.call_count == 1000
        assert ep.usage_frequency == 0.5


# ── _find_duplicate_paths ─────────────────────────────────────────────────

class TestFindDuplicatePaths:
    def test_detects_duplicates(self):
        ep_map = {
            "/items": [
                RouteEndpoint("/items", {"GET"}, "f1", "a.py", 1, None),
                RouteEndpoint("/items", {"GET"}, "f2", "b.py", 1, None),
            ],
            "/unique": [
                RouteEndpoint("/unique", {"GET"}, "f3", "c.py", 1, None),
            ],
        }
        dups = _find_duplicate_paths(ep_map)
        assert "/items" in dups
        assert "/unique" not in dups

    def test_no_duplicates(self):
        ep_map = {"/a": [RouteEndpoint("/a", {"GET"}, "f", "x.py", 1, None)]}
        assert _find_duplicate_paths(ep_map) == {}


# ── build_consolidation_plan ──────────────────────────────────────────────

class TestBuildConsolidationPlan:
    def test_phases_exist(self, router_tree: Path):
        router_files = list(router_tree.rglob("*router*.py"))
        routers = {}
        ep_map = {}
        for fp in router_files:
            info = _analyze_router_file(fp, router_tree)
            routers[fp] = info
            for ep in info.endpoints:
                ep_map.setdefault(ep.path, []).append(ep)

        plan = build_consolidation_plan(routers, ep_map)
        assert "phase1_cull" in plan
        assert "phase2_merge_duplicates" in plan
        assert "phase3_split_large" in plan
        assert "phase4_domain_consolidation" in plan

    def test_detects_merge_targets(self, router_tree: Path):
        router_files = list(router_tree.rglob("*router*.py"))
        routers = {}
        ep_map = {}
        for fp in router_files:
            info = _analyze_router_file(fp, router_tree)
            routers[fp] = info
            for ep in info.endpoints:
                ep_map.setdefault(ep.path, []).append(ep)

        plan = build_consolidation_plan(routers, ep_map)
        merge_paths = [t["path"] for t in plan["phase2_merge_duplicates"]]
        assert "/items" in merge_paths


# ── RoutersAnalyzer (full protocol) ───────────────────────────────────────

class TestRoutersAnalyzer:
    def test_protocol_fields(self):
        a = RoutersAnalyzer()
        assert a.id == "routers"
        assert a.version == "1.0.0"

    def test_run_returns_findings(self, router_tree: Path):
        a = RoutersAnalyzer(endpoints_warn=2, endpoints_high=10)
        files = list(router_tree.rglob("*.py"))
        findings = a.run(router_tree, files)
        assert len(findings) > 0
        assert all(f.type == AnalyzerType.ROUTERS for f in findings)

    def test_finding_ids_are_stable(self, router_tree: Path):
        a = RoutersAnalyzer(endpoints_warn=2)
        files = list(router_tree.rglob("*.py"))
        ids_1 = [f.finding_id for f in a.run(router_tree, files)]
        ids_2 = [f.finding_id for f in a.run(router_tree, files)]
        assert ids_1 == ids_2

    def test_detects_dense_router(self, router_tree: Path):
        a = RoutersAnalyzer(endpoints_warn=5, endpoints_high=15)
        files = list(router_tree.rglob("*.py"))
        findings = a.run(router_tree, files)
        dense = [f for f in findings if f.metadata.get("rule_id", "").startswith("RT-DENSE")]
        assert len(dense) >= 1

    def test_detects_duplicate_routes(self, router_tree: Path):
        a = RoutersAnalyzer()
        files = list(router_tree.rglob("*.py"))
        findings = a.run(router_tree, files)
        dups = [f for f in findings if f.metadata.get("rule_id") == "RT-DUP-001"]
        assert len(dups) >= 1
        assert "/items" in dups[0].message

    def test_ignores_non_router_files(self, router_tree: Path):
        a = RoutersAnalyzer()
        files = list(router_tree.rglob("*.py"))
        findings = a.run(router_tree, files)
        # models.py should not appear
        assert not any("models.py" in f.location.path for f in findings)

    def test_cull_with_analytics(self, router_tree: Path):
        analytics = {"list_items": {"call_count": 100_000, "frequency": 0.3}}
        # endpoint_0 through endpoint_19 have no analytics → cull
        a = RoutersAnalyzer(analytics=analytics)
        files = list(router_tree.rglob("*.py"))
        findings = a.run(router_tree, files)
        culls = [f for f in findings if f.metadata.get("rule_id") == "RT-CULL-001"]
        assert len(culls) >= 1

    def test_sprawl_finding(self, router_tree: Path):
        a = RoutersAnalyzer(total_routes_warn=5)
        files = list(router_tree.rglob("*.py"))
        findings = a.run(router_tree, files)
        sprawl = [f for f in findings if f.metadata.get("rule_id", "").startswith("RT-SPRAWL")]
        assert len(sprawl) == 1
        assert sprawl[0].metadata["total_routes"] >= 5


# ── generate_router_report ────────────────────────────────────────────────

class TestGenerateRouterReport:
    def test_produces_report_dict(self, router_tree: Path):
        report = generate_router_report(router_tree)
        assert "metrics" in report
        assert "classifications" in report
        assert "plan" in report
        assert report["metrics"]["total_files"] >= 2
        assert report["metrics"]["total_endpoints"] >= 3

    def test_writes_json_to_output_dir(self, router_tree: Path, tmp_path: Path):
        out = tmp_path / "report_out"
        generate_router_report(router_tree, output_dir=out)
        assert (out / "router_analysis.json").exists()
