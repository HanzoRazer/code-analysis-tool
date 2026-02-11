"""Tests for SafetyFenceAnalyzer and FenceRegistry."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from code_audit.contracts.safety_fence import SafetyFenceAnalyzer
from code_audit.contracts.fence_registry import FenceRegistry
from code_audit.model import AnalyzerType, Severity
from code_audit.model.fence import FenceDefinition, FenceLevel, FenceType


# ═══════════════════════════════════════════════════════════════════════
#  SafetyFenceAnalyzer
# ═══════════════════════════════════════════════════════════════════════

class TestSafetyFenceAnalyzer:
    """Unit tests for the safety fence checker."""

    def test_analyzer_protocol(self):
        """Analyzer has required id, version, run method."""
        analyzer = SafetyFenceAnalyzer()
        assert analyzer.id == "safety_fence"
        assert analyzer.version == "1.0.0"
        assert callable(analyzer.run)

    # ── bare-except checks ──────────────────────────────────────────

    def test_flags_bare_except(self, tmp_path: Path):
        """Bare except clauses produce SAFETY/HIGH findings."""
        code = textwrap.dedent("""\
            def risky():
                try:
                    do_something()
                except:
                    pass
        """)
        (tmp_path / "app.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "app.py"])

        bare = [f for f in findings if f.metadata.get("rule_id") == "FENCE-BARE-EXCEPT"]
        assert len(bare) == 1
        assert bare[0].type == AnalyzerType.SAFETY
        assert bare[0].severity == Severity.HIGH

    def test_ignores_specific_except(self, tmp_path: Path):
        """Named except clauses are not flagged."""
        code = textwrap.dedent("""\
            def safe():
                try:
                    do_something()
                except ValueError:
                    pass
        """)
        (tmp_path / "app.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "app.py"])

        bare = [f for f in findings if f.metadata.get("rule_id") == "FENCE-BARE-EXCEPT"]
        assert bare == []

    def test_bare_except_check_can_be_disabled(self, tmp_path: Path):
        """Setting check_bare_except=False skips that check."""
        code = textwrap.dedent("""\
            def risky():
                try:
                    x = 1
                except:
                    pass
        """)
        (tmp_path / "app.py").write_text(code)

        analyzer = SafetyFenceAnalyzer(check_bare_except=False)
        findings = analyzer.run(tmp_path, [tmp_path / "app.py"])

        bare = [f for f in findings if f.metadata.get("rule_id") == "FENCE-BARE-EXCEPT"]
        assert bare == []

    # ── safety-decorator checks ─────────────────────────────────────

    def test_flags_missing_safety_decorator(self, tmp_path: Path):
        """Safety-pattern function without @safety_critical is flagged CRITICAL."""
        code = textwrap.dedent("""\
            def generate_gcode(path):
                return "G01 X10 Y20"
        """)
        (tmp_path / "cnc.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "cnc.py"])

        dec = [f for f in findings if f.metadata.get("rule_id") == "FENCE-SAFETY-DECORATOR"]
        assert len(dec) == 1
        assert dec[0].type == AnalyzerType.SAFETY
        assert dec[0].severity == Severity.CRITICAL
        assert dec[0].metadata["function_name"] == "generate_gcode"

    def test_passes_with_decorator(self, tmp_path: Path):
        """Function WITH @safety_critical is not flagged."""
        code = textwrap.dedent("""\
            def safety_critical(fn):
                return fn

            @safety_critical
            def generate_gcode(path):
                return "G01 X10 Y20"
        """)
        (tmp_path / "cnc.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "cnc.py"])

        dec = [f for f in findings if f.metadata.get("rule_id") == "FENCE-SAFETY-DECORATOR"]
        assert dec == []

    def test_excludes_stub_suffix(self, tmp_path: Path):
        """Functions ending in _stub are excluded."""
        code = textwrap.dedent("""\
            def generate_gcode_stub():
                return "stub"
        """)
        (tmp_path / "cnc.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "cnc.py"])

        dec = [f for f in findings if f.metadata.get("rule_id") == "FENCE-SAFETY-DECORATOR"]
        assert dec == []

    def test_excludes_hash_suffix(self, tmp_path: Path):
        """Functions ending in _hash are excluded."""
        code = textwrap.dedent("""\
            def generate_gcode_hash():
                return "abc123"
        """)
        (tmp_path / "cnc.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "cnc.py"])

        dec = [f for f in findings if f.metadata.get("rule_id") == "FENCE-SAFETY-DECORATOR"]
        assert dec == []

    def test_excludes_protocol_class_methods(self, tmp_path: Path):
        """Methods inside Protocol classes are excluded."""
        code = textwrap.dedent("""\
            from typing import Protocol

            class MachineControl(Protocol):
                def generate_gcode(self) -> str: ...
        """)
        (tmp_path / "protocol.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "protocol.py"])

        dec = [f for f in findings if f.metadata.get("rule_id") == "FENCE-SAFETY-DECORATOR"]
        assert dec == []

    def test_custom_patterns(self, tmp_path: Path):
        """Custom safety_patterns override defaults."""
        code = textwrap.dedent("""\
            def my_critical_op():
                return 42
        """)
        (tmp_path / "ops.py").write_text(code)

        # Default patterns won't match "my_critical_op"
        analyzer_default = SafetyFenceAnalyzer()
        assert analyzer_default.run(tmp_path, [tmp_path / "ops.py"]) == []

        # Custom pattern does
        analyzer_custom = SafetyFenceAnalyzer(safety_patterns=[r"my_critical"])
        findings = analyzer_custom.run(tmp_path, [tmp_path / "ops.py"])
        assert len(findings) == 1
        assert findings[0].metadata["function_name"] == "my_critical_op"

    def test_finding_id_prefix(self, tmp_path: Path):
        """Safety fence findings get 'sf_' prefixed IDs."""
        code = textwrap.dedent("""\
            def generate_gcode():
                try:
                    pass
                except:
                    pass
        """)
        (tmp_path / "app.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        findings = analyzer.run(tmp_path, [tmp_path / "app.py"])

        assert len(findings) >= 1
        for f in findings:
            assert f.finding_id.startswith("sf_")

    def test_deterministic_fingerprints(self, tmp_path: Path):
        """Same code produces same fingerprints across runs."""
        code = textwrap.dedent("""\
            def generate_gcode():
                pass
        """)
        (tmp_path / "app.py").write_text(code)

        analyzer = SafetyFenceAnalyzer()
        run1 = analyzer.run(tmp_path, [tmp_path / "app.py"])
        run2 = analyzer.run(tmp_path, [tmp_path / "app.py"])

        assert [f.fingerprint for f in run1] == [f.fingerprint for f in run2]

    # ── integration with pipeline ────────────────────────────────────

    def test_works_in_run_scan(self, tmp_path: Path):
        """SafetyFenceAnalyzer integrates with the scan pipeline."""
        from code_audit.core.runner import run_scan

        code = textwrap.dedent("""\
            def calculate_feeds(rpm, depth):
                try:
                    return rpm * depth
                except:
                    return 0
        """)
        (tmp_path / "machine.py").write_text(code)

        result = run_scan(tmp_path, [SafetyFenceAnalyzer()])
        safety = [f for f in result.findings if f.type == AnalyzerType.SAFETY]
        assert len(safety) >= 1  # at least bare-except or missing decorator


# ═══════════════════════════════════════════════════════════════════════
#  FenceRegistry
# ═══════════════════════════════════════════════════════════════════════

class TestFenceRegistry:
    """Unit tests for the fence definition registry."""

    def test_builtins_loaded_by_default(self):
        """Registry has built-in fences on construction."""
        registry = FenceRegistry()
        assert len(registry) >= 2
        assert "safety_001" in registry
        assert "safety_002" in registry

    def test_no_builtins_option(self):
        """Can create empty registry without builtins."""
        registry = FenceRegistry(include_builtins=False)
        assert len(registry) == 0

    def test_register_custom_fence(self):
        """Programmatic registration works."""
        registry = FenceRegistry(include_builtins=False)
        fence = FenceDefinition(
            fence_id="custom_001",
            name="Test Fence",
            fence_type=FenceType.CUSTOM,
        )
        registry.register(fence)
        assert "custom_001" in registry
        assert registry.get("custom_001") is fence

    def test_list_all(self):
        """list() returns all fences sorted by id."""
        registry = FenceRegistry()
        fences = registry.list()
        assert len(fences) >= 2
        ids = [f.fence_id for f in fences]
        assert ids == sorted(ids)

    def test_list_filter_by_type(self):
        """list() can filter by fence_type."""
        registry = FenceRegistry()
        safety = registry.list(fence_type=FenceType.SAFETY)
        for f in safety:
            assert f.fence_type == FenceType.SAFETY

    def test_list_enabled_only(self):
        """list(enabled_only=True) excludes disabled fences."""
        registry = FenceRegistry(include_builtins=False)
        registry.register(FenceDefinition(
            fence_id="on_001", name="On", fence_type=FenceType.CUSTOM, enabled=True
        ))
        registry.register(FenceDefinition(
            fence_id="off_001", name="Off", fence_type=FenceType.CUSTOM, enabled=False
        ))
        enabled = registry.list(enabled_only=True)
        assert len(enabled) == 1
        assert enabled[0].fence_id == "on_001"

    def test_load_from_json_file(self, tmp_path: Path):
        """Can load fence definitions from a JSON file."""
        data = {
            "fences": [
                {
                    "fence_id": "json_001",
                    "name": "From JSON",
                    "fence_type": "import",
                    "level": "warning",
                    "description": "Test fence from file.",
                    "config": {"banned_modules": ["os.system"]},
                }
            ]
        }
        config_file = tmp_path / "fences.json"
        config_file.write_text(json.dumps(data))

        registry = FenceRegistry(include_builtins=False)
        count = registry.load_file(config_file)
        assert count == 1
        fence = registry.get("json_001")
        assert fence is not None
        assert fence.name == "From JSON"
        assert fence.fence_type == FenceType.IMPORT
        assert fence.level == FenceLevel.WARNING
        assert fence.config["banned_modules"] == ["os.system"]

    def test_get_returns_none_for_missing(self):
        """get() returns None for unknown IDs."""
        registry = FenceRegistry(include_builtins=False)
        assert registry.get("nope") is None


# ═══════════════════════════════════════════════════════════════════════
#  FenceDefinition model
# ═══════════════════════════════════════════════════════════════════════

class TestFenceDefinition:
    """Unit tests for the FenceDefinition dataclass."""

    def test_to_dict(self):
        """to_dict() produces a JSON-serializable dict."""
        fence = FenceDefinition(
            fence_id="test_001",
            name="Test",
            fence_type=FenceType.SAFETY,
            level=FenceLevel.CRITICAL,
            description="A test fence.",
        )
        d = fence.to_dict()
        assert d["fence_id"] == "test_001"
        assert d["fence_type"] == "safety"
        assert d["level"] == "critical"
        # Serializable
        json.dumps(d)

    def test_frozen(self):
        """FenceDefinition is immutable."""
        fence = FenceDefinition(
            fence_id="test_001",
            name="Test",
            fence_type=FenceType.SAFETY,
        )
        with pytest.raises(AttributeError):
            fence.fence_id = "changed"  # type: ignore[misc]
