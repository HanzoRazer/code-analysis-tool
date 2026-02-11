"""Tests for the governance gate analyzers (import_ban, deprecation, legacy_usage)."""

from __future__ import annotations

import json
import textwrap
from datetime import date, timedelta
from pathlib import Path

import pytest

from code_audit.governance.import_ban import ImportBanAnalyzer
from code_audit.governance.deprecation import DeprecationAnalyzer
from code_audit.governance.legacy_usage import LegacyUsageAnalyzer
from code_audit.model import AnalyzerType, Severity


# ════════════════════════════════════════════════════════════════════
# ImportBanAnalyzer
# ════════════════════════════════════════════════════════════════════


class TestImportBanAnalyzer:
    """Unit tests for the banned-import scanner."""

    def test_analyzer_protocol(self):
        a = ImportBanAnalyzer()
        assert a.id == "import_ban"
        assert a.version == "1.0.0"
        assert callable(a.run)

    def test_clean_file_no_findings(self, tmp_path: Path):
        code = textwrap.dedent("""\
            import os
            from pathlib import Path
            print("hello")
        """)
        (tmp_path / "clean.py").write_text(code)
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "clean.py"])
        assert findings == []

    def test_detects_from_import(self, tmp_path: Path):
        code = textwrap.dedent("""\
            from app._experimental.ai_core import Model
        """)
        (tmp_path / "bad.py").write_text(code)
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "bad.py"])
        assert len(findings) == 1
        f = findings[0]
        assert f.type == AnalyzerType.SECURITY
        assert f.severity == Severity.HIGH
        assert "app._experimental.ai_core" in f.message
        assert f.metadata["rule_id"] == "GOV-IMPORT-BAN"

    def test_detects_plain_import(self, tmp_path: Path):
        code = textwrap.dedent("""\
            import app._experimental.ai_core
        """)
        (tmp_path / "bad2.py").write_text(code)
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "bad2.py"])
        assert len(findings) == 1
        assert "GOV-IMPORT-BAN" in findings[0].snippet or findings[0].metadata["rule_id"] == "GOV-IMPORT-BAN"

    def test_custom_banned_pattern(self, tmp_path: Path):
        code = textwrap.dedent("""\
            from legacy_sdk.v1 import Client
            from modern_sdk import Client as C
        """)
        (tmp_path / "custom.py").write_text(code)
        analyzer = ImportBanAnalyzer(banned_patterns=[r"legacy_sdk\.v1"])
        findings = analyzer.run(tmp_path, [tmp_path / "custom.py"])
        assert len(findings) == 1
        assert "legacy_sdk.v1" in findings[0].message

    def test_multiple_violations_same_file(self, tmp_path: Path):
        code = textwrap.dedent("""\
            from app._experimental.ai_core import Foo
            import os
            from app._experimental.ai_core.utils import bar
        """)
        (tmp_path / "multi.py").write_text(code)
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "multi.py"])
        assert len(findings) == 2

    def test_skip_shim_files(self, tmp_path: Path):
        code = "from app._experimental.ai_core import Thing\n"
        (tmp_path / "ai_core_shim.py").write_text(code)
        findings = ImportBanAnalyzer(skip_shims=True).run(
            tmp_path, [tmp_path / "ai_core_shim.py"]
        )
        assert findings == []

    def test_no_skip_shim_when_disabled(self, tmp_path: Path):
        code = "from app._experimental.ai_core import Thing\n"
        (tmp_path / "ai_core_shim.py").write_text(code)
        findings = ImportBanAnalyzer(skip_shims=False).run(
            tmp_path, [tmp_path / "ai_core_shim.py"]
        )
        assert len(findings) == 1

    def test_syntax_error_skipped(self, tmp_path: Path):
        (tmp_path / "broken.py").write_text("def foo(\n")
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "broken.py"])
        assert findings == []

    def test_finding_location(self, tmp_path: Path):
        code = textwrap.dedent("""\
            import os
            import sys
            from app._experimental.ai_core import X
        """)
        (tmp_path / "loc.py").write_text(code)
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "loc.py"])
        assert len(findings) == 1
        assert findings[0].location.line_start == 3
        assert findings[0].location.path == "loc.py"

    def test_finding_ids_unique(self, tmp_path: Path):
        code = textwrap.dedent("""\
            from app._experimental.ai_core import A
            from app._experimental.ai_core.sub import B
        """)
        (tmp_path / "ids.py").write_text(code)
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "ids.py"])
        ids = [f.finding_id for f in findings]
        assert len(set(ids)) == len(ids)  # all unique

    def test_fingerprint_starts_with_sha256(self, tmp_path: Path):
        code = "from app._experimental.ai_core import Z\n"
        (tmp_path / "fp.py").write_text(code)
        findings = ImportBanAnalyzer().run(tmp_path, [tmp_path / "fp.py"])
        assert findings[0].fingerprint.startswith("sha256:")


# ════════════════════════════════════════════════════════════════════
# DeprecationAnalyzer
# ════════════════════════════════════════════════════════════════════


class TestDeprecationAnalyzer:
    """Unit tests for the deprecation-sunset scanner."""

    def test_analyzer_protocol(self):
        a = DeprecationAnalyzer()
        assert a.id == "deprecation_sunset"
        assert a.version == "1.0.0"
        assert callable(a.run)

    def test_no_registry_no_findings(self, tmp_path: Path):
        """When no registry file exists, return empty."""
        findings = DeprecationAnalyzer().run(tmp_path, [])
        assert findings == []

    def test_overdue_module_present(self, tmp_path: Path):
        """Module exists past its sunset → HIGH finding."""
        # Create the module file
        (tmp_path / "legacy").mkdir()
        (tmp_path / "legacy" / "old_handler.py").write_text("# old code\n")

        # Create registry with past date
        registry = {
            "routes": [
                {
                    "id": "old-route",
                    "module": "legacy.old_handler",
                    "sunset_date": "2024-01-01",
                    "old_prefix": "/api/v1/old",
                    "new_prefix": "/api/v2/handler",
                }
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))

        analyzer = DeprecationAnalyzer(
            reference_date=date(2025, 6, 15),
        )
        findings = analyzer.run(tmp_path, [])
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == Severity.HIGH
        assert f.type == AnalyzerType.DEAD_CODE
        assert "overdue" in f.message.lower()
        assert f.metadata["rule_id"] == "GOV-DEPR-OVERDUE"
        assert f.metadata["days_overdue"] > 0

    def test_overdue_warn_only(self, tmp_path: Path):
        """warn_only=True downgrades overdue findings to MEDIUM."""
        (tmp_path / "stale.py").write_text("# stale\n")
        registry = {
            "routes": [
                {"id": "r1", "module": "stale", "sunset_date": "2024-06-01"}
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(
            warn_only=True,
            reference_date=date(2025, 1, 1),
        )
        findings = analyzer.run(tmp_path, [])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_overdue_module_removed(self, tmp_path: Path):
        """Module already removed → no finding (mission accomplished)."""
        registry = {
            "routes": [
                {"id": "r1", "module": "gone_module", "sunset_date": "2024-01-01"}
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(reference_date=date(2025, 1, 1))
        findings = analyzer.run(tmp_path, [])
        assert findings == []

    def test_upcoming_sunset(self, tmp_path: Path):
        """Module approaching sunset → INFO finding."""
        (tmp_path / "soon.py").write_text("# retiring soon\n")
        in_20_days = date(2025, 6, 1) + timedelta(days=20)
        registry = {
            "routes": [
                {
                    "id": "soon-route",
                    "module": "soon",
                    "sunset_date": in_20_days.isoformat(),
                }
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(
            upcoming_days=30,
            reference_date=date(2025, 6, 1),
        )
        findings = analyzer.run(tmp_path, [])
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert findings[0].metadata["rule_id"] == "GOV-DEPR-UPCOMING"

    def test_upcoming_disabled(self, tmp_path: Path):
        """upcoming_days=0 suppresses upcoming warnings."""
        (tmp_path / "soon.py").write_text("# retiring soon\n")
        in_10_days = date(2025, 6, 1) + timedelta(days=10)
        registry = {
            "routes": [
                {"id": "r1", "module": "soon", "sunset_date": in_10_days.isoformat()}
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(
            upcoming_days=0,
            reference_date=date(2025, 6, 1),
        )
        findings = analyzer.run(tmp_path, [])
        assert findings == []

    def test_future_sunset_no_finding(self, tmp_path: Path):
        """Module with far-future sunset → no finding."""
        (tmp_path / "future.py").write_text("# fine\n")
        registry = {
            "routes": [
                {"id": "r1", "module": "future", "sunset_date": "2030-01-01"}
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(
            upcoming_days=30,
            reference_date=date(2025, 6, 1),
        )
        findings = analyzer.run(tmp_path, [])
        assert findings == []

    def test_custom_registry_path(self, tmp_path: Path):
        """registry_path parameter overrides default location."""
        sub = tmp_path / "conf"
        sub.mkdir()
        (tmp_path / "old_mod.py").write_text("# old\n")
        registry = {
            "routes": [
                {"id": "r1", "module": "old_mod", "sunset_date": "2024-01-01"}
            ]
        }
        reg_file = sub / "my_reg.json"
        reg_file.write_text(json.dumps(registry))

        analyzer = DeprecationAnalyzer(
            registry_path=reg_file,
            reference_date=date(2025, 1, 1),
        )
        findings = analyzer.run(tmp_path, [])
        assert len(findings) == 1

    def test_malformed_registry(self, tmp_path: Path):
        """Invalid JSON in registry → graceful empty return."""
        (tmp_path / "deprecation_registry.json").write_text("{bad json")
        findings = DeprecationAnalyzer().run(tmp_path, [])
        assert findings == []

    def test_multiple_routes(self, tmp_path: Path):
        """Multiple routes, mixed states."""
        (tmp_path / "dead.py").write_text("# dead\n")
        (tmp_path / "alive.py").write_text("# alive\n")
        registry = {
            "routes": [
                {"id": "r1", "module": "dead", "sunset_date": "2024-01-01"},
                {"id": "r2", "module": "alive", "sunset_date": "2030-06-01"},
                {"id": "r3", "module": "gone", "sunset_date": "2024-06-01"},
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(reference_date=date(2025, 1, 1))
        findings = analyzer.run(tmp_path, [])
        # Only r1 should fire — dead module present & overdue
        # r2 is future, r3 module doesn't exist
        assert len(findings) == 1
        assert findings[0].metadata["route_id"] == "r1"

    def test_new_prefix_in_message(self, tmp_path: Path):
        (tmp_path / "old.py").write_text("# old\n")
        registry = {
            "routes": [
                {
                    "id": "r1",
                    "module": "old",
                    "sunset_date": "2024-01-01",
                    "new_prefix": "/api/v3/new",
                }
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(reference_date=date(2025, 1, 1))
        findings = analyzer.run(tmp_path, [])
        assert "/api/v3/new" in findings[0].message

    def test_package_module_detection(self, tmp_path: Path):
        """Module can be a package directory with __init__.py."""
        pkg = tmp_path / "legacy_pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("# init\n")
        registry = {
            "routes": [
                {"id": "r1", "module": "legacy_pkg", "sunset_date": "2024-01-01"}
            ]
        }
        (tmp_path / "deprecation_registry.json").write_text(json.dumps(registry))
        analyzer = DeprecationAnalyzer(reference_date=date(2025, 1, 1))
        findings = analyzer.run(tmp_path, [])
        assert len(findings) == 1


# ════════════════════════════════════════════════════════════════════
# LegacyUsageAnalyzer
# ════════════════════════════════════════════════════════════════════


class TestLegacyUsageAnalyzer:
    """Unit tests for the legacy-usage gate."""

    def test_analyzer_protocol(self):
        a = LegacyUsageAnalyzer()
        assert a.id == "legacy_usage"
        assert a.version == "1.0.0"
        assert callable(a.run)

    def test_no_legacy_usage(self, tmp_path: Path):
        code = 'fetch("/api/v2/users")\n'
        (tmp_path / "clean.ts").write_text(code)
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "clean.ts"])
        assert findings == []

    def test_detects_legacy_v1_route(self, tmp_path: Path):
        code = 'const url = "/api/v1/users";\n'
        (tmp_path / "app.ts").write_text(code)
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "app.ts"])
        assert len(findings) == 1
        f = findings[0]
        assert f.type == AnalyzerType.DEAD_CODE
        assert f.severity == Severity.MEDIUM
        assert f.metadata["rule_id"] == "GOV-LEGACY-USAGE"
        assert "/api/v2/" in f.message  # suggests replacement

    def test_multiple_matches_same_file(self, tmp_path: Path):
        code = textwrap.dedent("""\
            fetch("/api/v1/users");
            fetch("/api/v2/items");
            fetch("/api/v1/orders");
        """)
        (tmp_path / "service.ts").write_text(code)
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "service.ts"])
        assert len(findings) == 2  # lines 1 and 3

    def test_custom_routes(self, tmp_path: Path):
        routes = [
            {"pattern": r"/old-endpoint/", "replacement": "/new-endpoint/", "label": "old-ep"},
        ]
        code = 'fetch("/old-endpoint/data");\n'
        (tmp_path / "custom.ts").write_text(code)
        analyzer = LegacyUsageAnalyzer(legacy_routes=routes)
        findings = analyzer.run(tmp_path, [tmp_path / "custom.ts"])
        assert len(findings) == 1
        assert "old-ep" in findings[0].message

    def test_routes_from_json_file(self, tmp_path: Path):
        routes = {
            "routes": [
                {"pattern": "/deprecated/", "replacement": "/current/", "label": "dep"},
            ]
        }
        reg = tmp_path / "routes.json"
        reg.write_text(json.dumps(routes))
        code = 'url = "/deprecated/thing";\n'
        (tmp_path / "caller.js").write_text(code)
        analyzer = LegacyUsageAnalyzer(legacy_routes=reg)
        findings = analyzer.run(tmp_path, [tmp_path / "caller.js"])
        assert len(findings) == 1

    def test_budget_under_limit(self, tmp_path: Path):
        code = 'fetch("/api/v1/users");\n'
        (tmp_path / "a.ts").write_text(code)
        analyzer = LegacyUsageAnalyzer(budget=5)
        findings = analyzer.run(tmp_path, [tmp_path / "a.ts"])
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM  # within budget

    def test_budget_over_limit_escalates(self, tmp_path: Path):
        code = "\n".join(f'fetch("/api/v1/item{i}");' for i in range(5))
        (tmp_path / "heavy.ts").write_text(code)
        analyzer = LegacyUsageAnalyzer(budget=2)
        findings = analyzer.run(tmp_path, [tmp_path / "heavy.ts"])
        assert len(findings) == 5
        for f in findings:
            assert f.severity == Severity.HIGH  # over budget → escalated

    def test_extension_filtering(self, tmp_path: Path):
        """Files with non-matching extensions are skipped."""
        (tmp_path / "readme.md").write_text("/api/v1/users\n")
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "readme.md"])
        assert findings == []

    def test_python_files_scanned(self, tmp_path: Path):
        code = 'url = "/api/v1/data"\n'
        (tmp_path / "backend.py").write_text(code)
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "backend.py"])
        assert len(findings) == 1

    def test_vue_files_scanned(self, tmp_path: Path):
        code = '<script>\nconst u = "/api/v1/stuff";\n</script>\n'
        (tmp_path / "comp.vue").write_text(code)
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "comp.vue"])
        assert len(findings) == 1

    def test_finding_ids_unique(self, tmp_path: Path):
        code = textwrap.dedent("""\
            fetch("/api/v1/a");
            fetch("/api/v1/b");
        """)
        (tmp_path / "u.ts").write_text(code)
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "u.ts"])
        ids = [f.finding_id for f in findings]
        assert len(set(ids)) == len(ids)

    def test_location_accuracy(self, tmp_path: Path):
        code = textwrap.dedent("""\
            // line 1
            // line 2
            const x = "/api/v1/here";
        """)
        (tmp_path / "loc.ts").write_text(code)
        findings = LegacyUsageAnalyzer().run(tmp_path, [tmp_path / "loc.ts"])
        assert len(findings) == 1
        assert findings[0].location.line_start == 3
        assert findings[0].location.path == "loc.ts"


# ════════════════════════════════════════════════════════════════════
# Integration: governance CLI dispatch
# ════════════════════════════════════════════════════════════════════


class TestGovernanceCLI:
    """Smoke tests for the governance CLI subcommands."""

    def test_import_ban_cli_clean(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "clean.py").write_text("import os\n")
        rc = main(["governance", "import-ban", str(tmp_path)])
        assert rc == 0

    def test_import_ban_cli_violation(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "bad.py").write_text("from app._experimental.ai_core import X\n")
        rc = main(["governance", "import-ban", str(tmp_path)])
        assert rc == 1

    def test_deprecation_cli_no_registry(self, tmp_path: Path):
        from code_audit.__main__ import main

        rc = main(["governance", "deprecation", str(tmp_path)])
        assert rc == 0

    def test_legacy_usage_cli_clean(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "app.ts").write_text('fetch("/api/v2/ok");\n')
        rc = main(["governance", "legacy-usage", str(tmp_path)])
        assert rc == 0
