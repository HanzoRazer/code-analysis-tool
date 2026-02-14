"""Unit tests for GlobalStateAnalyzer — AST detection of mutable state patterns."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from code_audit.analyzers.global_state import GlobalStateAnalyzer
from code_audit.model import AnalyzerType, Severity


@pytest.fixture()
def analyzer() -> GlobalStateAnalyzer:
    return GlobalStateAnalyzer()


def _write(tmp_path: Path, code: str, name: str = "target.py") -> Path:
    """Write *code* to a temp .py file and return the file path."""
    p = tmp_path / name
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


# ── module-level mutable assignments ─────────────────────────────────


class TestModuleMutableDetected:
    """GST_MUTABLE_MODULE_001 fires on module-level mutable literals/calls."""

    def test_empty_list(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "CACHE = []\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        f = findings[0]
        assert f.type == AnalyzerType.GLOBAL_STATE
        assert f.severity == Severity.MEDIUM
        assert f.metadata["rule_id"] == "GST_MUTABLE_MODULE_001"
        assert "CACHE" in f.snippet

    def test_empty_dict(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "DATA = {}\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_MODULE_001"

    def test_set_constructor(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "FLAGS = set()\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_MODULE_001"

    def test_list_constructor(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "ITEMS = list()\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_MODULE_001"

    def test_dict_constructor(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "MAPPING = dict()\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_MODULE_001"

    def test_annotated_assignment(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "ITEMS: list = []\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_MODULE_001"

    def test_multiple_module_mutables(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "A = []\nB = {}\nC = set()\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        module_findings = [
            f for f in findings if f.metadata["rule_id"] == "GST_MUTABLE_MODULE_001"
        ]
        assert len(module_findings) == 3


# ── mutable default arguments ─────────────────────────────────────────


class TestMutableDefaultDetected:
    """GST_MUTABLE_DEFAULT_001 fires on mutable default arguments."""

    def test_list_default(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "def foo(x=[]):\n    pass\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        f = findings[0]
        assert f.type == AnalyzerType.GLOBAL_STATE
        assert f.severity == Severity.HIGH
        assert f.confidence == 0.92
        assert f.metadata["rule_id"] == "GST_MUTABLE_DEFAULT_001"

    def test_dict_default(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "def foo(x={}):\n    pass\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_DEFAULT_001"

    def test_set_default(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "def foo(x=set()):\n    pass\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_DEFAULT_001"

    def test_kwonly_mutable_default(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "def foo(*, opts=dict()):\n    pass\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 1
        assert findings[0].metadata["rule_id"] == "GST_MUTABLE_DEFAULT_001"


# ── global keyword ────────────────────────────────────────────────────


class TestGlobalKeywordDetected:
    """GST_GLOBAL_KEYWORD_001 fires on ``global`` inside a function."""

    def test_single_global(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "X = 0\ndef inc():\n    global X\n    X += 1\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        gst = [f for f in findings if f.metadata["rule_id"] == "GST_GLOBAL_KEYWORD_001"]
        assert len(gst) == 1
        assert gst[0].severity == Severity.MEDIUM
        assert gst[0].confidence == 0.80
        assert "global X" in gst[0].snippet

    def test_multiple_names(self, analyzer: GlobalStateAnalyzer, tmp_path: Path) -> None:
        _write(tmp_path, "A = 0\nB = 0\ndef reset():\n    global A, B\n    A = B = 0\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        gst = [f for f in findings if f.metadata["rule_id"] == "GST_GLOBAL_KEYWORD_001"]
        assert len(gst) == 1
        assert "A, B" in gst[0].snippet


# ── negative cases (should NOT flag) ─────────────────────────────────


class TestNonMutableNotFlagged:
    """Immutable defaults and module constants must not trigger findings."""

    @pytest.mark.parametrize(
        "code",
        [
            "def f(x=None): pass",
            "def f(x=()): pass",
            "def f(x=0): pass",
            "def f(x=''): pass",
            "def f(x=True): pass",
            "def f(x=frozenset()): pass",
            "def f(x=(1, 2, 3)): pass",
        ],
        ids=["None", "tuple", "int", "str", "bool", "frozenset", "tuple_literal"],
    )
    def test_immutable_defaults_ignored(
        self, analyzer: GlobalStateAnalyzer, tmp_path: Path, code: str,
    ) -> None:
        _write(tmp_path, code + "\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 0

    @pytest.mark.parametrize(
        "code",
        [
            "THRESHOLD = 100",
            'NAME = "app"',
            "COORDS = (1, 2, 3)",
            "ENABLED = True",
        ],
        ids=["int", "str", "tuple", "bool"],
    )
    def test_immutable_module_constants_ignored(
        self, analyzer: GlobalStateAnalyzer, tmp_path: Path, code: str,
    ) -> None:
        _write(tmp_path, code + "\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 0

    def test_local_mutable_not_flagged(
        self, analyzer: GlobalStateAnalyzer, tmp_path: Path,
    ) -> None:
        """Mutable assignment inside a function body is NOT module-level."""
        _write(tmp_path, "def compute():\n    result = []\n    return result\n")
        findings = analyzer.run(tmp_path, list(tmp_path.glob("*.py")))
        assert len(findings) == 0


# ── integration with fixture repos ───────────────────────────────────


class TestFixtureRepos:
    """End-to-end detection on the global_state fixture repos."""

    FIXTURES = Path(__file__).resolve().parent / "fixtures" / "repos"

    def test_hot_repo_detects_all_patterns(self, analyzer: GlobalStateAnalyzer) -> None:
        root = self.FIXTURES / "global_state_hot"
        files = sorted(root.rglob("*.py"))
        findings = analyzer.run(root, files)

        rules = {f.metadata["rule_id"] for f in findings}
        assert "GST_MUTABLE_MODULE_001" in rules
        assert "GST_MUTABLE_DEFAULT_001" in rules
        assert "GST_GLOBAL_KEYWORD_001" in rules

        # Exact counts from hot fixture: 3 module mutables, 1 mutable default, 1 global
        module = [f for f in findings if f.metadata["rule_id"] == "GST_MUTABLE_MODULE_001"]
        defaults = [f for f in findings if f.metadata["rule_id"] == "GST_MUTABLE_DEFAULT_001"]
        globals_ = [f for f in findings if f.metadata["rule_id"] == "GST_GLOBAL_KEYWORD_001"]
        assert len(module) == 3
        assert len(defaults) == 1
        assert len(globals_) == 1

    def test_clean_repo_no_findings(self, analyzer: GlobalStateAnalyzer) -> None:
        root = self.FIXTURES / "global_state_clean"
        files = sorted(root.rglob("*.py"))
        findings = analyzer.run(root, files)
        assert findings == []

    def test_finding_ids_are_stable(self, analyzer: GlobalStateAnalyzer) -> None:
        """Two runs on the same repo produce identical finding_ids."""
        root = self.FIXTURES / "global_state_hot"
        files = sorted(root.rglob("*.py"))
        ids1 = [f.finding_id for f in analyzer.run(root, files)]
        ids2 = [f.finding_id for f in analyzer.run(root, files)]
        assert ids1 == ids2

    def test_paths_are_posix(self, analyzer: GlobalStateAnalyzer) -> None:
        """Paths in findings use forward slashes (posix)."""
        root = self.FIXTURES / "global_state_hot"
        files = sorted(root.rglob("*.py"))
        findings = analyzer.run(root, files)
        for f in findings:
            assert "\\" not in f.location.path, f"backslash in path: {f.location.path}"


# ── signal translation ───────────────────────────────────────────────


class TestGlobalStateSignal:
    """Translator produces exactly one global_state signal."""

    def test_single_aggregated_signal(self, analyzer: GlobalStateAnalyzer) -> None:
        root = Path(__file__).resolve().parent / "fixtures" / "repos" / "global_state_hot"
        files = sorted(root.rglob("*.py"))
        findings = analyzer.run(root, files)

        from code_audit.insights.translator import findings_to_signals

        signals = findings_to_signals(findings)
        gst_signals = [s for s in signals if s["type"] == "global_state"]
        assert len(gst_signals) == 1, f"Expected 1 global_state signal, got {len(gst_signals)}"

        sig = gst_signals[0]
        assert sig["risk_level"] in ("yellow", "red")
        assert sig["evidence"]["summary"]["mutable_default_count"] == 1
        assert sig["evidence"]["summary"]["module_mutable_count"] == 3
        assert sig["evidence"]["summary"]["global_keyword_count"] == 1
        assert len(sig["evidence"]["finding_ids"]) == 5

    def test_no_signal_when_clean(self, analyzer: GlobalStateAnalyzer) -> None:
        root = Path(__file__).resolve().parent / "fixtures" / "repos" / "global_state_clean"
        files = sorted(root.rglob("*.py"))
        findings = analyzer.run(root, files)

        from code_audit.insights.translator import findings_to_signals

        signals = findings_to_signals(findings)
        gst_signals = [s for s in signals if s["type"] == "global_state"]
        assert len(gst_signals) == 0


# ── API integration ──────────────────────────────────────────────────


class TestAPIIntegration:
    """scan_project includes global_state findings and by_type counts."""

    FIXTURES = Path(__file__).resolve().parent / "fixtures" / "repos"

    def test_scan_hot_includes_global_state(self) -> None:
        from code_audit.api import scan_project

        _, result_dict = scan_project(
            self.FIXTURES / "global_state_hot", ci_mode=True,
        )
        by_type = result_dict["summary"]["counts"]["by_type"]
        assert "global_state" in by_type
        assert by_type["global_state"] >= 5  # 3 module + 1 default + 1 global

        # Exactly one global_state signal
        gst_signals = [
            s for s in result_dict["signals_snapshot"] if s["type"] == "global_state"
        ]
        assert len(gst_signals) == 1

    def test_scan_clean_no_global_state(self) -> None:
        from code_audit.api import scan_project

        _, result_dict = scan_project(
            self.FIXTURES / "global_state_clean", ci_mode=True,
        )
        by_type = result_dict["summary"]["counts"]["by_type"]
        assert "global_state" not in by_type

        gst_signals = [
            s for s in result_dict["signals_snapshot"] if s["type"] == "global_state"
        ]
        assert len(gst_signals) == 0
