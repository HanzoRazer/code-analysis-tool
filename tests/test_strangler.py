"""Tests for the Strangler Fig module (P5 — debt detection, plan gen, registry)."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from code_audit.model import AnalyzerType, Severity
from code_audit.model.debt_instance import (
    DebtInstance,
    DebtType,
    REFACTORING_STRATEGY,
    make_debt_fingerprint,
)
from code_audit.strangler.debt_detector import DebtDetector
from code_audit.strangler.plan_generator import generate_plan
from code_audit.strangler.debt_registry import DebtRegistry, DebtDiff


# ════════════════════════════════════════════════════════════════════
# DebtInstance model
# ════════════════════════════════════════════════════════════════════


class TestDebtInstance:
    def test_to_dict(self):
        d = DebtInstance(
            debt_type=DebtType.GOD_CLASS,
            path="mod.py",
            symbol="BigClass",
            line_start=1,
            line_end=200,
            metrics={"methods": 15},
            strategy="Extract Class",
            fingerprint="sha256:abc",
        )
        result = d.to_dict()
        assert result["debt_type"] == "god_class"
        assert result["symbol"] == "BigClass"
        assert result["metrics"]["methods"] == 15

    def test_make_debt_fingerprint(self):
        fp = make_debt_fingerprint("god_class", "mod.py", "BigClass")
        assert fp.startswith("sha256:")
        # Deterministic
        assert fp == make_debt_fingerprint("god_class", "mod.py", "BigClass")

    def test_refactoring_strategy_enum_coverage(self):
        """Every DebtType has a refactoring strategy."""
        for dt in DebtType:
            assert dt in REFACTORING_STRATEGY


# ════════════════════════════════════════════════════════════════════
# DebtDetector
# ════════════════════════════════════════════════════════════════════


class TestDebtDetector:
    def test_protocol(self):
        d = DebtDetector()
        assert d.id == "debt_detector"
        assert d.version == "1.0.0"
        assert callable(d.run)

    def test_clean_code_no_findings(self, tmp_path: Path):
        code = textwrap.dedent("""\
            def greet(name):
                return f"Hello, {name}!"

            class Small:
                def __init__(self):
                    self.x = 1

                def method(self):
                    return self.x
        """)
        (tmp_path / "clean.py").write_text(code)
        findings = DebtDetector().run(tmp_path, [tmp_path / "clean.py"])
        assert findings == []

    def test_god_class_by_methods(self, tmp_path: Path):
        methods = "\n".join(
            f"    def method_{i}(self):\n        return {i}\n"
            for i in range(12)
        )
        code = f"class Huge:\n{methods}\n"
        (tmp_path / "god.py").write_text(code)
        detector = DebtDetector(god_class_methods=10)
        findings = detector.run(tmp_path, [tmp_path / "god.py"])
        god_findings = [
            f for f in findings if f.metadata.get("rule_id") == "DEBT-GOD-CLASS"
        ]
        assert len(god_findings) == 1
        assert god_findings[0].type == AnalyzerType.COMPLEXITY
        assert god_findings[0].severity == Severity.MEDIUM
        assert "God Class" in god_findings[0].message
        assert god_findings[0].metadata["methods"] == 12

    def test_god_class_by_attrs(self, tmp_path: Path):
        attrs = "\n".join(f"        self.attr_{i} = {i}" for i in range(20))
        code = f"class BigData:\n    def __init__(self):\n{attrs}\n"
        (tmp_path / "attrs.py").write_text(code)
        detector = DebtDetector(god_class_attrs=15)
        findings = detector.run(tmp_path, [tmp_path / "attrs.py"])
        gc = [f for f in findings if f.metadata.get("rule_id") == "DEBT-GOD-CLASS"]
        assert len(gc) == 1
        assert gc[0].metadata["attributes"] == 20

    def test_god_function(self, tmp_path: Path):
        body = "\n".join(f"    x_{i} = {i}" for i in range(70))
        code = f"def monster():\n{body}\n    return x_0\n"
        (tmp_path / "monster.py").write_text(code)
        detector = DebtDetector(god_function_lines=60)
        findings = detector.run(tmp_path, [tmp_path / "monster.py"])
        gf = [f for f in findings if f.metadata.get("rule_id") == "DEBT-GOD-FUNC"]
        assert len(gf) == 1
        assert "God Function" in gf[0].message
        assert gf[0].metadata["lines"] >= 60

    def test_deep_nesting(self, tmp_path: Path):
        code = textwrap.dedent("""\
            def nested(x):
                if x > 0:
                    for i in range(x):
                        if i > 1:
                            while i > 2:
                                if i > 3:
                                    return i
                return 0
        """)
        (tmp_path / "nested.py").write_text(code)
        detector = DebtDetector(deep_nesting_depth=4)
        findings = detector.run(tmp_path, [tmp_path / "nested.py"])
        dn = [f for f in findings if f.metadata.get("rule_id") == "DEBT-DEEP-NEST"]
        assert len(dn) == 1
        assert dn[0].severity == Severity.LOW
        assert dn[0].metadata["nesting_depth"] >= 4

    def test_long_parameter_list(self, tmp_path: Path):
        code = textwrap.dedent("""\
            def configure(a, b, c, d, e, f, g, h):
                return a + b + c + d + e + f + g + h
        """)
        (tmp_path / "params.py").write_text(code)
        detector = DebtDetector(long_param_count=6)
        findings = detector.run(tmp_path, [tmp_path / "params.py"])
        lp = [
            f for f in findings if f.metadata.get("rule_id") == "DEBT-LONG-PARAMS"
        ]
        assert len(lp) == 1
        assert lp[0].metadata["param_count"] == 8

    def test_self_cls_excluded_from_param_count(self, tmp_path: Path):
        code = textwrap.dedent("""\
            class C:
                def method(self, a, b, c, d, e):
                    pass
        """)
        (tmp_path / "method.py").write_text(code)
        detector = DebtDetector(long_param_count=6)
        findings = detector.run(tmp_path, [tmp_path / "method.py"])
        lp = [
            f for f in findings if f.metadata.get("rule_id") == "DEBT-LONG-PARAMS"
        ]
        # 5 params (excluding self) < 6
        assert lp == []

    def test_syntax_error_skipped(self, tmp_path: Path):
        (tmp_path / "broken.py").write_text("def foo(\n")
        findings = DebtDetector().run(tmp_path, [tmp_path / "broken.py"])
        assert findings == []

    def test_detect_returns_debt_instances(self, tmp_path: Path):
        methods = "\n".join(
            f"    def m_{i}(self):\n        return {i}\n" for i in range(12)
        )
        code = f"class Big:\n{methods}\n"
        (tmp_path / "big.py").write_text(code)
        detector = DebtDetector(god_class_methods=10)
        items = detector.detect(tmp_path, [tmp_path / "big.py"])
        assert len(items) >= 1
        assert all(isinstance(i, DebtInstance) for i in items)
        gc = [i for i in items if i.debt_type == DebtType.GOD_CLASS]
        assert len(gc) == 1

    def test_finding_ids_unique(self, tmp_path: Path):
        methods = "\n".join(
            f"    def m_{i}(self):\n        return {i}\n" for i in range(12)
        )
        body = "\n".join(f"    x_{i} = {i}" for i in range(70))
        code = f"class Big:\n{methods}\n\ndef monster():\n{body}\n    return x_0\n"
        (tmp_path / "multi.py").write_text(code)
        detector = DebtDetector(god_class_methods=10, god_function_lines=60)
        findings = detector.run(tmp_path, [tmp_path / "multi.py"])
        ids = [f.finding_id for f in findings]
        assert len(set(ids)) == len(ids)

    def test_custom_thresholds(self, tmp_path: Path):
        """Very low thresholds should flag ordinary code."""
        code = textwrap.dedent("""\
            class Small:
                def a(self): return 1
                def b(self): return 2
                def c(self): return 3
        """)
        (tmp_path / "small.py").write_text(code)
        detector = DebtDetector(god_class_methods=2)
        findings = detector.run(tmp_path, [tmp_path / "small.py"])
        assert any(f.metadata.get("rule_id") == "DEBT-GOD-CLASS" for f in findings)

    def test_multiple_files(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("def f(a,b,c,d,e,f,g): pass\n")
        (tmp_path / "b.py").write_text("def g(x,y,z,w,u,v,t): pass\n")
        detector = DebtDetector(long_param_count=6)
        findings = detector.run(
            tmp_path, [tmp_path / "a.py", tmp_path / "b.py"]
        )
        lp = [f for f in findings if f.metadata.get("rule_id") == "DEBT-LONG-PARAMS"]
        assert len(lp) == 2


# ════════════════════════════════════════════════════════════════════
# PlanGenerator
# ════════════════════════════════════════════════════════════════════


class TestPlanGenerator:
    def test_empty_items_produces_clean_plan(self):
        plan = generate_plan([])
        assert "No structural debt detected" in plan

    def test_plan_has_header(self):
        items = [
            DebtInstance(
                debt_type=DebtType.GOD_FUNCTION,
                path="big.py",
                symbol="monster",
                line_start=1,
                line_end=100,
                metrics={"lines": 100},
                strategy="Extract Method",
                fingerprint="sha256:abc",
            )
        ]
        plan = generate_plan(items)
        assert "# Strangler Fig" in plan
        assert "Refactoring Plan" in plan

    def test_plan_includes_project_id(self):
        items = [
            DebtInstance(
                debt_type=DebtType.DEEP_NESTING,
                path="m.py",
                symbol="f",
                line_start=1,
                line_end=10,
                fingerprint="sha256:x",
            )
        ]
        plan = generate_plan(items, project_id="my-project")
        assert "my-project" in plan

    def test_summary_table(self):
        items = [
            DebtInstance(
                debt_type=DebtType.GOD_FUNCTION,
                path="a.py",
                symbol="f1",
                line_start=1,
                line_end=80,
                metrics={"lines": 80},
                strategy="Extract Method",
                fingerprint="sha256:a",
            ),
            DebtInstance(
                debt_type=DebtType.GOD_FUNCTION,
                path="b.py",
                symbol="f2",
                line_start=1,
                line_end=90,
                metrics={"lines": 90},
                strategy="Extract Method",
                fingerprint="sha256:b",
            ),
            DebtInstance(
                debt_type=DebtType.DEEP_NESTING,
                path="c.py",
                symbol="f3",
                line_start=1,
                line_end=20,
                metrics={"nesting_depth": 6},
                strategy="Guard Clauses",
                fingerprint="sha256:c",
            ),
        ]
        plan = generate_plan(items)
        assert "## Summary" in plan
        assert "god_function" in plan
        assert "deep_nesting" in plan
        assert "| 2 |" in plan  # 2 god functions

    def test_work_items_prioritised(self):
        items = [
            DebtInstance(
                debt_type=DebtType.DEEP_NESTING,
                path="a.py",
                symbol="deep",
                line_start=1,
                line_end=10,
                fingerprint="sha256:1",
            ),
            DebtInstance(
                debt_type=DebtType.GOD_FUNCTION,
                path="b.py",
                symbol="god",
                line_start=1,
                line_end=80,
                fingerprint="sha256:2",
            ),
        ]
        plan = generate_plan(items)
        # God Function (P1) should appear before Deep Nesting (P3)
        god_pos = plan.index("god")
        deep_pos = plan.index("deep")
        assert god_pos < deep_pos

    def test_plan_includes_strategy(self):
        items = [
            DebtInstance(
                debt_type=DebtType.GOD_CLASS,
                path="x.py",
                symbol="Big",
                line_start=1,
                line_end=200,
                strategy="Extract Class / Extract Interface",
                fingerprint="sha256:x",
            ),
        ]
        plan = generate_plan(items)
        assert "Extract Class" in plan

    def test_plan_footer(self):
        items = [
            DebtInstance(
                debt_type=DebtType.GOD_FUNCTION,
                path="a.py",
                symbol="f",
                line_start=1,
                line_end=80,
                fingerprint="sha256:f",
            ),
        ]
        plan = generate_plan(items)
        assert "Plan generated by code-audit" in plan


# ════════════════════════════════════════════════════════════════════
# DebtRegistry
# ════════════════════════════════════════════════════════════════════


class TestDebtRegistry:
    def _make_item(
        self, dtype: DebtType = DebtType.GOD_FUNCTION, symbol: str = "fn"
    ) -> DebtInstance:
        fp = make_debt_fingerprint(dtype.value, "m.py", symbol)
        return DebtInstance(
            debt_type=dtype,
            path="m.py",
            symbol=symbol,
            line_start=1,
            line_end=50,
            metrics={"lines": 80},
            strategy="Extract Method",
            fingerprint=fp,
        )

    def test_save_and_load(self, tmp_path: Path):
        reg = DebtRegistry(tmp_path / "snaps")
        item = self._make_item()
        reg.save_snapshot("baseline", [item])
        loaded = reg.load_snapshot("baseline")
        assert len(loaded) == 1
        assert loaded[0].debt_type == DebtType.GOD_FUNCTION
        assert loaded[0].symbol == "fn"

    def test_list_snapshots(self, tmp_path: Path):
        reg = DebtRegistry(tmp_path / "snaps")
        reg.save_snapshot("alpha", [])
        reg.save_snapshot("beta", [self._make_item()])
        names = reg.list_snapshots()
        assert names == ["alpha", "beta"]

    def test_list_empty(self, tmp_path: Path):
        reg = DebtRegistry(tmp_path / "empty")
        assert reg.list_snapshots() == []

    def test_load_missing_raises(self, tmp_path: Path):
        reg = DebtRegistry(tmp_path / "snaps")
        with pytest.raises(FileNotFoundError):
            reg.load_snapshot("nope")

    def test_compare_no_changes(self):
        items = [self._make_item()]
        diff = DebtRegistry.compare(items, items)
        assert diff.new_items == []
        assert diff.resolved_items == []
        assert len(diff.unchanged_items) == 1
        assert not diff.has_new_debt

    def test_compare_new_debt(self):
        old = [self._make_item(symbol="old")]
        new = [self._make_item(symbol="old"), self._make_item(symbol="new")]
        diff = DebtRegistry.compare(old, new)
        assert len(diff.new_items) == 1
        assert diff.new_items[0].symbol == "new"
        assert diff.has_new_debt

    def test_compare_resolved_debt(self):
        old = [self._make_item(symbol="gone"), self._make_item(symbol="stays")]
        new = [self._make_item(symbol="stays")]
        diff = DebtRegistry.compare(old, new)
        assert len(diff.resolved_items) == 1
        assert diff.resolved_items[0].symbol == "gone"
        assert not diff.has_new_debt

    def test_diff_summary(self):
        diff = DebtDiff(
            new_items=[self._make_item(symbol="a")],
            resolved_items=[self._make_item(symbol="b")],
            unchanged_items=[self._make_item(symbol="c")],
        )
        s = diff.summary()
        assert "New: 1" in s
        assert "Resolved: 1" in s
        assert "Unchanged: 1" in s

    def test_round_trip_preserves_fingerprint(self, tmp_path: Path):
        reg = DebtRegistry(tmp_path / "snaps")
        item = self._make_item()
        reg.save_snapshot("test", [item])
        loaded = reg.load_snapshot("test")
        assert loaded[0].fingerprint == item.fingerprint


# ════════════════════════════════════════════════════════════════════
# CLI smoke tests
# ════════════════════════════════════════════════════════════════════


class TestDebtCLI:
    def test_debt_scan_clean(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "clean.py").write_text("x = 1\n")
        rc = main(["debt", "scan", str(tmp_path)])
        assert rc == 0

    def test_debt_scan_violation(self, tmp_path: Path):
        from code_audit.__main__ import main

        body = "\n".join(f"    x_{i} = {i}" for i in range(70))
        code = f"def monster():\n{body}\n    return x_0\n"
        (tmp_path / "big.py").write_text(code)
        rc = main(["debt", "scan", str(tmp_path)])
        assert rc == 1

    def test_debt_plan_stdout(self, tmp_path: Path, capsys):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")
        rc = main(["debt", "plan", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "Strangler Fig" in out or "No structural debt" in out

    def test_debt_plan_to_file(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")
        out = tmp_path / "plan.md"
        rc = main(["debt", "plan", str(tmp_path), "--output", str(out)])
        assert rc == 0
        assert out.exists()

    def test_debt_snapshot_and_compare(self, tmp_path: Path):
        from code_audit.__main__ import main

        body = "\n".join(f"    x_{i} = {i}" for i in range(70))
        code = f"def monster():\n{body}\n    return x_0\n"
        (tmp_path / "big.py").write_text(code)

        # Take snapshot
        rc = main([
            "debt", "snapshot", str(tmp_path),
            "--name", "v1",
            "--registry-dir", str(tmp_path / ".snaps"),
        ])
        assert rc == 0
        assert (tmp_path / ".snaps" / "v1.json").exists()

        # Compare (no changes → exit 0)
        rc = main([
            "debt", "compare", str(tmp_path),
            "--baseline", "v1",
            "--registry-dir", str(tmp_path / ".snaps"),
        ])
        assert rc == 0

    def test_debt_compare_new_debt_exits_1(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")

        # Take clean snapshot
        rc = main([
            "debt", "snapshot", str(tmp_path),
            "--name", "clean",
            "--registry-dir", str(tmp_path / ".snaps"),
        ])
        assert rc == 0

        # Add debt
        body = "\n".join(f"    x_{i} = {i}" for i in range(70))
        code = f"def monster():\n{body}\n    return x_0\n"
        (tmp_path / "big.py").write_text(code)

        # Compare → new debt → exit 1
        rc = main([
            "debt", "compare", str(tmp_path),
            "--baseline", "clean",
            "--registry-dir", str(tmp_path / ".snaps"),
        ])
        assert rc == 1

    def test_debt_compare_missing_baseline(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")
        rc = main([
            "debt", "compare", str(tmp_path),
            "--baseline", "nonexistent",
            "--registry-dir", str(tmp_path / ".snaps"),
        ])
        assert rc == 2

    def test_debt_nonexistent_path(self):
        from code_audit.__main__ import main

        rc = main(["debt", "scan", "/nonexistent/xyz"])
        assert rc == 2
