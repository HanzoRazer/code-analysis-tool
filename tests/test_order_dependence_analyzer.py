"""Unit tests for the order-dependence / silent-shadowing detector.

Flags where load/registration order silently decides the winner: a registration
key claimed 2+ times in a module (route/registry), or a duplicate key in a
dict/set literal. v1 records explicit_precedence_confirmed=False for the v2 pass.
"""
from __future__ import annotations

from pathlib import Path

from code_audit.analyzers.order_dependence import OrderDependenceAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(src, encoding="utf-8")
    return OrderDependenceAnalyzer().run(tmp_path, [p])


# ── registration collisions (the killer sub-check) ──────────────────


def test_duplicate_route_same_method_flagged(tmp_path):
    src = (
        "app = object()\n"
        '@app.get("/health")\n'
        "def h1(): ...\n"
        '@app.get("/health")\n'
        "def h2(): ...\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.ORDER_DEPENDENCE
    assert f[0].metadata["rule_id"] == "ORDER_DEP_REGISTRY_001"
    assert f[0].metadata["key"] == "/health"
    assert f[0].severity is Severity.MEDIUM
    assert f[0].metadata["explicit_precedence_confirmed"] is False
    assert f[0].finding_id


def test_same_path_different_method_not_collision(tmp_path):
    # GET /x and POST /x are distinct routes — method-aware, not a collision.
    src = (
        "app = object()\n"
        '@app.get("/x")\n'
        "def a(): ...\n"
        '@app.post("/x")\n'
        "def b(): ...\n"
    )
    assert _run(tmp_path, src) == []


def test_different_paths_not_flagged(tmp_path):
    src = (
        "r = object()\n"
        '@r.get("/x")\n'
        "def a(): ...\n"
        '@r.get("/y")\n'
        "def b(): ...\n"
    )
    assert _run(tmp_path, src) == []


def test_parametrize_is_not_a_registry_collision(tmp_path):
    # Configuration decorator: same param name on two functions is normal.
    src = (
        "import pytest\n"
        '@pytest.mark.parametrize("val", [1, 2])\n'
        "def test_a(val): ...\n"
        '@pytest.mark.parametrize("val", [3, 4])\n'
        "def test_b(val): ...\n"
    )
    assert _run(tmp_path, src) == []


def test_explicit_registry_register_collision(tmp_path):
    src = (
        "registry = object()\n"
        '@registry.register("plugin")\n'
        "def p1(): ...\n"
        '@registry.register("plugin")\n'
        "def p2(): ...\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert f[0].metadata["key"] == "plugin"


def test_collision_records_all_sites(tmp_path):
    src = (
        "app = object()\n"
        '@app.get("/x")\n'
        "def a(): ...\n"
        '@app.get("/x")\n'
        "def b(): ...\n"
        '@app.get("/x")\n'
        "def c(): ...\n"
    )
    f = _run(tmp_path, src)
    assert len(f) == 1
    assert len(f[0].metadata["sites"]) == 3


# ── duplicate literal keys ──────────────────────────────────────────


def test_dict_duplicate_key_flagged(tmp_path):
    f = _run(tmp_path, 'D = {"a": 1, "b": 2, "a": 3}\n')
    assert len(f) == 1
    assert f[0].metadata["rule_id"] == "ORDER_DEP_DUP_KEY_001"
    assert f[0].metadata["duplicate_key"] == "'a'"
    assert f[0].severity is Severity.LOW


def test_set_duplicate_key_flagged(tmp_path):
    f = _run(tmp_path, "S = {1, 2, 1}\n")
    assert len(f) == 1
    assert f[0].metadata["literal_kind"] == "set"


def test_dict_no_duplicate_no_finding(tmp_path):
    assert _run(tmp_path, 'D = {"a": 1, "b": 2}\n') == []


def test_dict_spread_does_not_crash(tmp_path):
    assert _run(tmp_path, 'D = {"a": 1, **other}\n') == []


def test_clean_module_no_findings(tmp_path):
    assert _run(tmp_path, "def add(a, b):\n    return a + b\n") == []
