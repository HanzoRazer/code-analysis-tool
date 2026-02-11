"""Tests for P6 Supporting Modules — feature_hunt, sdk_boundary, parse_truth_map."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from code_audit.model import AnalyzerType, Severity
from code_audit.inventory.feature_hunt import FeatureHuntAnalyzer, FeatureFlagHit
from code_audit.governance.sdk_boundary import SdkBoundaryAnalyzer
from code_audit.utils.parse_truth_map import (
    EndpointEntry,
    parse_truth_map,
    truth_map_to_set,
    diff_truth_map,
)


# ════════════════════════════════════════════════════════════════════
# FeatureHuntAnalyzer
# ════════════════════════════════════════════════════════════════════


class TestFeatureHunt:
    def test_protocol(self):
        a = FeatureHuntAnalyzer()
        assert a.id == "feature_hunt"
        assert a.version == "1.0.0"
        assert callable(a.run)

    def test_clean_code_no_findings(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\nprint(x)\n")
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "app.py"])
        assert findings == []

    def test_detects_feature_constant(self, tmp_path: Path):
        code = "FEATURE_NEW_UI = True\n"
        (tmp_path / "config.py").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "config.py"])
        hits = [f for f in findings if f.metadata.get("pattern_label") == "feature-constant"]
        assert len(hits) >= 1
        assert "FEATURE_NEW_UI" in hits[0].message

    def test_detects_ff_constant(self, tmp_path: Path):
        (tmp_path / "flags.py").write_text("FF_DARK_MODE = False\n")
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "flags.py"])
        assert any(f.metadata.get("pattern_label") == "ff-constant" for f in findings)

    def test_detects_env_feature_flag(self, tmp_path: Path):
        code = 'enabled = os.environ.get("FEATURE_X", "0")\n'
        (tmp_path / "env.py").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "env.py"])
        assert any(f.metadata.get("pattern_label") == "env-feature-flag" for f in findings)

    def test_detects_flag_sdk(self, tmp_path: Path):
        code = 'if feature_flags.is_enabled("dark_mode"):\n    do_stuff()\n'
        (tmp_path / "sdk.py").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "sdk.py"])
        assert any(f.metadata.get("pattern_label") == "feature-flag-sdk" for f in findings)

    def test_detects_is_enabled(self, tmp_path: Path):
        code = 'if flags.is_enabled("X"):\n    pass\n'
        (tmp_path / "check.py").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "check.py"])
        assert any(
            f.metadata.get("pattern_label") == "flag-is-enabled" for f in findings
        )

    def test_detects_feature_toggle(self, tmp_path: Path):
        code = "value = feature_toggle.get('beta')\n"
        (tmp_path / "toggle.py").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "toggle.py"])
        assert any(
            f.metadata.get("pattern_label") == "feature-toggle" for f in findings
        )

    def test_detects_typescript(self, tmp_path: Path):
        code = 'const enabled = FEATURE_WIDGET_V2;\n'
        (tmp_path / "config.ts").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "config.ts"])
        assert any(
            f.metadata.get("pattern_label") == "feature-constant" for f in findings
        )

    def test_skips_unsupported_extensions(self, tmp_path: Path):
        (tmp_path / "data.json").write_text('{"FEATURE_X": true}\n')
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "data.json"])
        assert findings == []

    def test_extra_patterns(self, tmp_path: Path):
        code = "use_beta_feature()\n"
        (tmp_path / "app.py").write_text(code)
        analyzer = FeatureHuntAnalyzer(
            extra_patterns=[(r"use_beta_\w+", "custom-beta")],
            include_defaults=False,
        )
        findings = analyzer.run(tmp_path, [tmp_path / "app.py"])
        assert len(findings) == 1
        assert findings[0].metadata["pattern_label"] == "custom-beta"

    def test_no_defaults(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("FEATURE_X = True\n")
        analyzer = FeatureHuntAnalyzer(include_defaults=False)
        findings = analyzer.run(tmp_path, [tmp_path / "app.py"])
        assert findings == []

    def test_hunt_convenience(self, tmp_path: Path):
        (tmp_path / "f.py").write_text("FF_DARK = True\n")
        analyzer = FeatureHuntAnalyzer()
        hits = analyzer.hunt(tmp_path, [tmp_path / "f.py"])
        assert isinstance(hits[0], FeatureFlagHit)
        assert hits[0].pattern_label == "ff-constant"

    def test_finding_fields(self, tmp_path: Path):
        (tmp_path / "c.py").write_text("FEATURE_ABC = True\n")
        f = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "c.py"])[0]
        assert f.type == AnalyzerType.DEAD_CODE
        assert f.severity == Severity.INFO
        assert f.finding_id.startswith("fh_")
        assert f.fingerprint.startswith("sha256:")
        assert f.metadata["rule_id"] == "INV-FEATURE-FLAG"

    def test_multiple_flags_same_file(self, tmp_path: Path):
        code = "FEATURE_A = True\nFEATURE_B = False\nFF_C = 1\n"
        (tmp_path / "multi.py").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "multi.py"])
        assert len(findings) >= 3

    def test_multiple_files(self, tmp_path: Path):
        (tmp_path / "a.py").write_text("FEATURE_X = 1\n")
        (tmp_path / "b.py").write_text("FF_Y = 2\n")
        findings = FeatureHuntAnalyzer().run(
            tmp_path, [tmp_path / "a.py", tmp_path / "b.py"]
        )
        assert len(findings) >= 2

    def test_ids_unique(self, tmp_path: Path):
        code = "FEATURE_A = True\nFEATURE_B = False\n"
        (tmp_path / "u.py").write_text(code)
        findings = FeatureHuntAnalyzer().run(tmp_path, [tmp_path / "u.py"])
        ids = [f.finding_id for f in findings]
        assert len(set(ids)) == len(ids)


# ════════════════════════════════════════════════════════════════════
# SdkBoundaryAnalyzer
# ════════════════════════════════════════════════════════════════════


class TestSdkBoundary:
    def test_protocol(self):
        a = SdkBoundaryAnalyzer()
        assert a.id == "sdk_boundary"
        assert a.version == "1.0.0"
        assert callable(a.run)

    def test_clean_code_no_findings(self, tmp_path: Path):
        code = 'const data = sdk.getWidgets();\n'
        (tmp_path / "component.ts").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "component.ts"])
        assert findings == []

    def test_detects_fetch_direct(self, tmp_path: Path):
        code = 'const res = fetch("/api/v2/users");\n'
        (tmp_path / "page.ts").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "page.ts"])
        assert len(findings) == 1
        assert "fetch-direct" in findings[0].metadata["pattern_label"]
        assert findings[0].severity == Severity.MEDIUM

    def test_detects_axios_direct(self, tmp_path: Path):
        code = "const res = axios.get('/api/widgets');\n"
        (tmp_path / "service.js").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "service.js"])
        assert any(f.metadata["pattern_label"] == "axios-direct" for f in findings)

    def test_detects_http_post(self, tmp_path: Path):
        code = 'http.post("/api/orders", body);\n'
        (tmp_path / "order.ts").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "order.ts"])
        assert len(findings) >= 1

    def test_detects_template_literal(self, tmp_path: Path):
        code = 'const res = fetch(`/api/items/${id}`);\n'
        (tmp_path / "item.tsx").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "item.tsx"])
        assert len(findings) >= 1

    def test_skips_comments(self, tmp_path: Path):
        code = '// fetch("/api/v2/users");\nconst x = 1;\n'
        (tmp_path / "clean.ts").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "clean.ts"])
        assert findings == []

    def test_skips_python_files(self, tmp_path: Path):
        code = 'requests.get("/api/things")\n'
        (tmp_path / "backend.py").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "backend.py"])
        assert findings == []

    def test_allowed_files(self, tmp_path: Path):
        sdk_dir = tmp_path / "sdk"
        sdk_dir.mkdir()
        code = 'const res = fetch("/api/users");\n'
        (sdk_dir / "client.ts").write_text(code)
        analyzer = SdkBoundaryAnalyzer(allowed_files=["sdk/*.ts"])
        findings = analyzer.run(tmp_path, [sdk_dir / "client.ts"])
        assert findings == []

    def test_custom_api_prefix(self, tmp_path: Path):
        code = 'fetch("/internal/v1/data");\n'
        (tmp_path / "page.js").write_text(code)
        # Default prefix /api/ doesn't match
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "page.js"])
        assert findings == []
        # Custom prefix matches
        analyzer = SdkBoundaryAnalyzer(api_prefixes=["/internal/v1/"])
        findings = analyzer.run(tmp_path, [tmp_path / "page.js"])
        assert len(findings) >= 1

    def test_multiple_violations_same_file(self, tmp_path: Path):
        code = textwrap.dedent("""\
            const a = fetch("/api/users");
            const b = axios.get("/api/orders");
            const c = http.post("/api/items", {});
        """)
        (tmp_path / "multi.tsx").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "multi.tsx"])
        assert len(findings) >= 3

    def test_vue_file(self, tmp_path: Path):
        code = '<script>\nconst data = fetch("/api/reports");\n</script>\n'
        (tmp_path / "Report.vue").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "Report.vue"])
        assert len(findings) >= 1

    def test_finding_fields(self, tmp_path: Path):
        code = 'fetch("/api/data");\n'
        (tmp_path / "x.ts").write_text(code)
        f = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "x.ts"])[0]
        assert f.type == AnalyzerType.SECURITY
        assert f.finding_id.startswith("sb_")
        assert f.fingerprint.startswith("sha256:")
        assert f.metadata["rule_id"] == "GOV-SDK-BOUNDARY"

    def test_ids_unique(self, tmp_path: Path):
        code = 'fetch("/api/a");\nfetch("/api/b");\n'
        (tmp_path / "u.ts").write_text(code)
        findings = SdkBoundaryAnalyzer().run(tmp_path, [tmp_path / "u.ts"])
        ids = [f.finding_id for f in findings]
        assert len(set(ids)) == len(ids)


# ════════════════════════════════════════════════════════════════════
# parse_truth_map
# ════════════════════════════════════════════════════════════════════


_SAMPLE_MAP = textwrap.dedent("""\
    # Endpoint Truth Map

    | Method | Path             | Module              | Status     |
    |--------|------------------|---------------------|------------|
    | GET    | /api/v2/widgets  | app.routes.widgets  | active     |
    | POST   | /api/v2/widgets  | app.routes.widgets  | active     |
    | GET    | /api/v1/legacy   | app.routes.legacy   | deprecated |
    | DELETE | /api/v2/items    | app.routes.items    | active     |
""")


class TestParseTruthMap:
    def test_parse_basic(self):
        entries = parse_truth_map(_SAMPLE_MAP)
        assert len(entries) == 4
        assert entries[0].method == "GET"
        assert entries[0].path == "/api/v2/widgets"
        assert entries[0].module == "app.routes.widgets"
        assert entries[0].status == "active"

    def test_deprecated_status(self):
        entries = parse_truth_map(_SAMPLE_MAP)
        legacy = [e for e in entries if e.status == "deprecated"]
        assert len(legacy) == 1
        assert legacy[0].path == "/api/v1/legacy"

    def test_to_dict(self):
        entries = parse_truth_map(_SAMPLE_MAP)
        d = entries[0].to_dict()
        assert d["method"] == "GET"
        assert d["path"] == "/api/v2/widgets"
        assert d["module"] == "app.routes.widgets"
        assert d["status"] == "active"

    def test_truth_map_to_set(self):
        entries = parse_truth_map(_SAMPLE_MAP)
        s = truth_map_to_set(entries)
        assert ("GET", "/api/v2/widgets") in s
        assert ("DELETE", "/api/v2/items") in s
        assert len(s) == 4

    def test_diff_no_difference(self):
        entries = parse_truth_map(_SAMPLE_MAP)
        actual = truth_map_to_set(entries)
        missing, unexpected = diff_truth_map(entries, actual)
        assert missing == []
        assert unexpected == []

    def test_diff_missing_endpoint(self):
        entries = parse_truth_map(_SAMPLE_MAP)
        actual = {("GET", "/api/v2/widgets")}  # missing POST and DELETE
        missing, unexpected = diff_truth_map(entries, actual)
        # 2 active endpoints are missing: POST /api/v2/widgets, DELETE /api/v2/items
        assert len(missing) == 2
        assert unexpected == []

    def test_diff_unexpected_endpoint(self):
        entries = parse_truth_map(_SAMPLE_MAP)
        actual = truth_map_to_set(entries) | {("GET", "/api/v3/new")}
        missing, unexpected = diff_truth_map(entries, actual)
        assert missing == []
        assert ("GET", "/api/v3/new") in unexpected

    def test_diff_deprecated_not_missing(self):
        """Deprecated routes should not be flagged as missing even if absent."""
        entries = parse_truth_map(_SAMPLE_MAP)
        # Actual has everything except the deprecated route
        actual = {
            ("GET", "/api/v2/widgets"),
            ("POST", "/api/v2/widgets"),
            ("DELETE", "/api/v2/items"),
        }
        missing, unexpected = diff_truth_map(entries, actual)
        assert missing == []

    def test_from_file(self, tmp_path: Path):
        md = tmp_path / "ENDPOINTS.md"
        md.write_text(_SAMPLE_MAP)
        entries = parse_truth_map(md)
        assert len(entries) == 4

    def test_no_table_raises(self):
        with pytest.raises(ValueError, match="No Markdown table"):
            parse_truth_map("# Just a heading\n\nNo table here.\n")

    def test_missing_required_column(self):
        bad_map = textwrap.dedent("""\
            | Verb   | URL  |
            |--------|------|
            | GET    | /x   |
        """)
        with pytest.raises(ValueError, match="Required column 'method'"):
            parse_truth_map(bad_map)

    def test_custom_required_columns(self):
        md = textwrap.dedent("""\
            | Method | Path  | Owner |
            |--------|-------|-------|
            | GET    | /x    | team  |
        """)
        entries = parse_truth_map(md, required_columns=("method", "path", "owner"))
        assert len(entries) == 1
        assert entries[0].extra["owner"] == "team"

    def test_extra_columns(self):
        md = textwrap.dedent("""\
            | Method | Path  | Module | Status | Owner  |
            |--------|-------|--------|--------|--------|
            | GET    | /api  | m.x    | active | team-a |
        """)
        entries = parse_truth_map(md)
        assert entries[0].extra["owner"] == "team-a"

    def test_empty_table(self):
        md = textwrap.dedent("""\
            | Method | Path |
            |--------|------|
        """)
        entries = parse_truth_map(md)
        assert entries == []


# ════════════════════════════════════════════════════════════════════
# CLI smoke tests
# ════════════════════════════════════════════════════════════════════


class TestP6CLI:
    def test_inventory_clean(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "app.py").write_text("x = 1\n")
        rc = main(["inventory", str(tmp_path)])
        assert rc == 0

    def test_inventory_finds_flags(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "config.py").write_text("FEATURE_BETA = True\n")
        rc = main(["inventory", str(tmp_path)])
        assert rc == 1

    def test_inventory_json(self, tmp_path: Path, capsys):
        from code_audit.__main__ import main

        (tmp_path / "f.py").write_text("FEATURE_X = 1\n")
        rc = main(["inventory", str(tmp_path), "--json"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_inventory_nonexistent(self):
        from code_audit.__main__ import main

        rc = main(["inventory", "/nonexistent/xyz"])
        assert rc == 2

    def test_sdk_boundary_clean(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "app.ts").write_text("const x = sdk.get();\n")
        rc = main(["sdk-boundary", str(tmp_path)])
        assert rc == 0

    def test_sdk_boundary_violation(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "page.ts").write_text('const r = fetch("/api/data");\n')
        rc = main(["sdk-boundary", str(tmp_path)])
        assert rc == 1

    def test_sdk_boundary_json(self, tmp_path: Path, capsys):
        from code_audit.__main__ import main

        (tmp_path / "v.js").write_text('axios.get("/api/things");\n')
        rc = main(["sdk-boundary", str(tmp_path), "--json"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_sdk_boundary_nonexistent(self):
        from code_audit.__main__ import main

        rc = main(["sdk-boundary", "/nonexistent/xyz"])
        assert rc == 2

    def test_truth_map_parse(self, tmp_path: Path):
        from code_audit.__main__ import main

        md = tmp_path / "ENDPOINTS.md"
        md.write_text(_SAMPLE_MAP)
        rc = main(["truth-map", str(md)])
        assert rc == 0

    def test_truth_map_json(self, tmp_path: Path, capsys):
        from code_audit.__main__ import main

        md = tmp_path / "ENDPOINTS.md"
        md.write_text(_SAMPLE_MAP)
        rc = main(["truth-map", str(md), "--json"])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 4
        assert data[0]["method"] == "GET"

    def test_truth_map_nonexistent(self):
        from code_audit.__main__ import main

        rc = main(["truth-map", "/nonexistent/endpoints.md"])
        assert rc == 2

    def test_truth_map_invalid(self, tmp_path: Path):
        from code_audit.__main__ import main

        (tmp_path / "bad.md").write_text("# No table\n")
        rc = main(["truth-map", str(tmp_path / "bad.md")])
        assert rc == 2
