"""Tests for namespace-authority drift engine + advisory suite adapter."""
from __future__ import annotations

import json
from pathlib import Path

from code_audit.analyzers.namespace_authority_drift import (
    NamespaceAuthorityContext,
    NamespaceAuthorityDriftAnalyzer,
)
from code_audit.analyzers.namespace_authority_engine import (
    FLAGGED_VERDICTS,
    AuthorityTopology,
    CandidateChange,
    NamespaceChange,
    Verdict,
    analyze_namespace_authority_drift,
)
from code_audit.model import AnalyzerType, Severity

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "namespace_authority"


def _nc(**kw) -> NamespaceChange:
    base = dict(namespace="x", path="services/api/app/x", change="added")
    base.update(kw)
    return NamespaceChange(**base)


def _synth_topo() -> AuthorityTopology:
    registry = json.loads((FIXTURES / "synth_registry.json").read_text(encoding="utf-8"))
    bindings = json.loads((FIXTURES / "synth_bindings.json").read_text(encoding="utf-8"))
    return AuthorityTopology(registry, namespace_bindings=bindings)


def _binding_less() -> dict:
    return json.loads((FIXTURES / "binding_less_registry.json").read_text(encoding="utf-8"))


# ── engine verdict families (synthetic bindings) ────────────────────


def test_engine_verdict_families():
    topo = _synth_topo()
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="notes", path="docs/n.md", is_code_namespace=False)]),
        topo,
    )[0].verdict is Verdict.NO_AUTHORITY_IMPACT
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="retopo")]), topo,
    )[0].verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="boe")]), topo,
    )[0].verdict is Verdict.DECLARED_EXTENSION
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="rival", declared_domain="geometry", declared_concept="Rival")]),
        topo,
    )[0].verdict is Verdict.DUPLICATE_AUTHORITY
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="boe", introduces_parallel_registry=True)]),
        topo,
    )[0].verdict is Verdict.PARALLEL_AUTHORITY
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="boe", restores_superseded=True)]),
        topo,
    )[0].verdict is Verdict.OBSOLETE_AUTHORITY
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="boe", violates_invariant="x")]),
        topo,
    )[0].verdict is Verdict.AUTHORITY_BYPASS
    assert analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="brandnew")]), topo,
    )[0].verdict is Verdict.NOVEL_VALID


def test_engine_does_not_infer_from_suggestive_names():
    """Anti-inference: binding-less topology with tempting domain names."""
    topo = AuthorityTopology(_binding_less(), namespace_bindings={})
    for ns in ("retopo", "body_outline", "geometry", "topology"):
        v = analyze_namespace_authority_drift(
            CandidateChange("b", "c", [_nc(namespace=ns, path=f"services/api/app/{ns}")]),
            topo,
        )[0]
        assert v.verdict is Verdict.INSUFFICIENT_EVIDENCE
        assert v.verdict not in FLAGGED_VERDICTS


# ── retopo + BOE integration fixtures (binding-less topology) ───────


def test_retopo_dogfood_insufficient_evidence():
    change = CandidateChange(
        "origin/main",
        "feature/mesh-pipeline-scaffold",
        [_nc(namespace="retopo", path="services/api/app/retopo")],
    )
    drifts = analyze_namespace_authority_drift(change, _binding_less())
    assert len(drifts) == 1
    assert drifts[0].verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert drifts[0].verdict not in FLAGGED_VERDICTS
    assert "binding" in drifts[0].evidence.lower()


def test_boe_control_not_flagged_by_age():
    change = CandidateChange(
        "dd86866c~1",
        "dd86866c",
        [_nc(
            namespace="body_outline",
            path="services/api/app/cam/translators/dxf/body_outline_translator.py",
        )],
    )
    drifts = analyze_namespace_authority_drift(change, _binding_less())
    assert drifts[0].verdict is Verdict.INSUFFICIENT_EVIDENCE
    assert drifts[0].verdict not in FLAGGED_VERDICTS


# ── suite adapter ───────────────────────────────────────────────────


def test_adapter_silent_without_context(tmp_path: Path):
    assert NamespaceAuthorityDriftAnalyzer().run(tmp_path, []) == []


def test_adapter_normalizes_retopo_finding(tmp_path: Path):
    change = CandidateChange(
        "origin/main",
        "feature/mesh-pipeline-scaffold",
        [_nc(namespace="retopo", path="services/api/app/retopo")],
    )
    ctx = NamespaceAuthorityContext(
        change=change,
        topology=FIXTURES / "binding_less_registry.json",
        source_registry="fixtures/binding_less_registry.json",
    )
    findings = NamespaceAuthorityDriftAnalyzer(review_context=ctx).run(tmp_path, [])
    assert len(findings) == 1
    f = findings[0]
    assert f.type is AnalyzerType.NAMESPACE_AUTHORITY_DRIFT
    assert f.metadata["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert f.metadata["flagged"] is False
    assert f.metadata["posture"] == "advisory"
    assert f.severity is Severity.LOW
    assert "governance review" in f.message.lower()
    assert "invent" in f.message.lower()
    assert f.finding_id == f.fingerprint


def test_adapter_never_guesses_domain_in_message(tmp_path: Path):
    change = CandidateChange("b", "c", [_nc(namespace="retopo", path="services/api/app/retopo")])
    findings = NamespaceAuthorityDriftAnalyzer(
        review_context=NamespaceAuthorityContext(change=change, topology=_binding_less())
    ).run(tmp_path, [])
    msg = findings[0].message.lower()
    assert "belongs to topology" not in msg
    assert "retopo ∈" not in msg


def test_adapter_maps_flagged_verdict_advisory_low(tmp_path: Path):
    change = CandidateChange(
        "b", "c",
        [_nc(namespace="rival", declared_domain="geometry", declared_concept="Rival")],
    )
    findings = NamespaceAuthorityDriftAnalyzer(
        review_context=NamespaceAuthorityContext(
            change=change,
            topology=_synth_topo(),
            source_registry="synth",
        )
    ).run(tmp_path, [])
    assert findings[0].metadata["verdict"] == "DUPLICATE_AUTHORITY"
    assert findings[0].metadata["flagged"] is True
    assert findings[0].metadata["severity_native"] == "warning"
    assert findings[0].severity is Severity.LOW  # advisory posture


def test_adapter_rejects_malformed_review_context_mapping():
    import pytest
    from jsonschema import ValidationError

    with pytest.raises(ValidationError):
        NamespaceAuthorityDriftAnalyzer(review_context={"topology": {}})
    with pytest.raises(ValidationError):
        NamespaceAuthorityDriftAnalyzer(
            review_context={
                "schema_version": "namespace_authority_context_v1",
                "change": "nope",
                "topology": {},
            }
        )
    # Legacy object-bearing dicts are rejected (must be JSON-serializable v1).
    with pytest.raises(ValidationError):
        NamespaceAuthorityDriftAnalyzer(
            review_context={
                "schema_version": "namespace_authority_context_v1",
                "change": CandidateChange("b", "c", [_nc(namespace="retopo")]),
                "topology": {},
            }
        )


def test_declared_domain_is_trusted_pre_resolved_not_name_inference():
    """Pin parity: declared_domain is a caller-supplied binding, not inference.

    Without it (and without a topology binding), suggestive names stay
    INSUFFICIENT_EVIDENCE. With an explicit declared_domain naming a real
    domain, resolve honors that trusted claim — upstream must not invent it.
    """
    topo = AuthorityTopology(_binding_less(), namespace_bindings={})
    unbound = analyze_namespace_authority_drift(
        CandidateChange("b", "c", [_nc(namespace="retopo")]),
        topo,
    )[0]
    assert unbound.verdict is Verdict.INSUFFICIENT_EVIDENCE

    trusted = analyze_namespace_authority_drift(
        CandidateChange(
            "b",
            "c",
            [_nc(namespace="retopo", declared_domain="topology", declared_concept="Retopo")],
        ),
        topo,
    )[0]
    # topology domain owners are TopologyBuilder / ShellValidation —
    # Retopo is not among them → DUPLICATE_AUTHORITY under pin semantics.
    assert trusted.verdict is Verdict.DUPLICATE_AUTHORITY


def test_bindings_kwarg_honored_when_topology_is_authority_topology():
    registry = json.loads((FIXTURES / "synth_registry.json").read_text(encoding="utf-8"))
    topo = AuthorityTopology(registry, namespace_bindings={})
    change = CandidateChange("b", "c", [_nc(namespace="boe")])
    assert (
        analyze_namespace_authority_drift(change, topo)[0].verdict
        is Verdict.INSUFFICIENT_EVIDENCE
    )
    bindings = json.loads((FIXTURES / "synth_bindings.json").read_text(encoding="utf-8"))
    assert (
        analyze_namespace_authority_drift(
            change, topo, namespace_bindings=bindings,
        )[0].verdict
        is Verdict.DECLARED_EXTENSION
    )


def test_scan_project_wires_namespace_authority_context(tmp_path: Path):
    from code_audit.api import scan_project

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    change = CandidateChange(
        "origin/main",
        "feature/mesh-pipeline-scaffold",
        [_nc(namespace="retopo", path="services/api/app/retopo")],
    )
    ctx = NamespaceAuthorityContext(
        change=change,
        topology=FIXTURES / "binding_less_registry.json",
        source_registry="fixtures/binding_less_registry.json",
    )
    silent, _ = scan_project(tmp_path, ci_mode=True)
    assert not any(
        getattr(f, "type", None) is AnalyzerType.NAMESPACE_AUTHORITY_DRIFT
        for f in silent.findings
    )

    active, result_dict = scan_project(
        tmp_path,
        ci_mode=True,
        namespace_authority_context=ctx,
    )
    ns_findings = [
        f for f in active.findings
        if f.type is AnalyzerType.NAMESPACE_AUTHORITY_DRIFT
    ]
    assert len(ns_findings) == 1
    assert ns_findings[0].metadata["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert ns_findings[0].metadata["posture"] == "advisory"
    assert isinstance(result_dict, dict)

    # Serialized v1 mapping / path activation (not object-bearing dicts).
    mapping = json.loads((FIXTURES / "context_valid.json").read_text(encoding="utf-8"))
    mapped, _ = scan_project(
        tmp_path,
        ci_mode=True,
        namespace_authority_context=mapping,
    )
    assert any(
        f.type is AnalyzerType.NAMESPACE_AUTHORITY_DRIFT
        and f.metadata.get("source_registry") == "fixture:binding-less"
        for f in mapped.findings
    )

    via_path, _ = scan_project(
        tmp_path,
        ci_mode=True,
        namespace_authority_context=FIXTURES / "context_valid.json",
    )
    assert any(
        f.type is AnalyzerType.NAMESPACE_AUTHORITY_DRIFT
        and f.metadata.get("verdict") == "INSUFFICIENT_EVIDENCE"
        for f in via_path.findings
    )

    # Path-as-string activation (str is a filesystem path, not a JSON blob).
    via_str, _ = scan_project(
        tmp_path,
        ci_mode=True,
        namespace_authority_context=str(FIXTURES / "context_valid.json"),
    )
    assert any(
        f.type is AnalyzerType.NAMESPACE_AUTHORITY_DRIFT
        and f.metadata.get("verdict") == "INSUFFICIENT_EVIDENCE"
        for f in via_str.findings
    )


# ── serialized loader contract edges ────────────────────────────────


def test_schema_dual_copy_byte_parity():
    repo = Path(__file__).resolve().parents[1]
    root_copy = repo / "schemas" / "namespace_authority_context.schema.json"
    runtime_copy = (
        repo
        / "src"
        / "code_audit"
        / "data"
        / "schemas"
        / "namespace_authority_context.schema.json"
    )
    assert root_copy.is_file() and runtime_copy.is_file()
    assert root_copy.read_bytes() == runtime_copy.read_bytes()


def test_loader_accepts_mapping_path_and_path_string():
    from types import MappingProxyType

    from code_audit.contracts.namespace_authority_context import (
        load_namespace_authority_context,
    )

    mapping = json.loads((FIXTURES / "context_valid.json").read_text(encoding="utf-8"))
    via_mapping = load_namespace_authority_context(mapping)
    via_proxy = load_namespace_authority_context(MappingProxyType(mapping))
    via_path = load_namespace_authority_context(FIXTURES / "context_valid.json")
    via_str = load_namespace_authority_context(str(FIXTURES / "context_valid.json"))

    assert via_mapping.change.namespace_changes[0].namespace == "retopo"
    assert via_proxy.source_registry == "fixture:binding-less"
    assert via_path.change.candidate_ref == "feature/mesh-pipeline-scaffold"
    assert via_str.source_registry == via_path.source_registry


def test_loader_rejects_raw_json_string_payload():
    import pytest

    from code_audit.contracts.namespace_authority_context import (
        load_namespace_authority_context,
    )

    raw = (FIXTURES / "context_valid.json").read_text(encoding="utf-8")
    with pytest.raises(TypeError, match="filesystem path"):
        load_namespace_authority_context(raw)


def test_loader_rejects_nonexistent_and_malformed_json(tmp_path: Path):
    import pytest

    from code_audit.contracts.namespace_authority_context import (
        load_namespace_authority_context,
    )

    missing = tmp_path / "missing-context.json"
    with pytest.raises(FileNotFoundError, match="does not exist"):
        load_namespace_authority_context(missing)
    with pytest.raises(FileNotFoundError, match="does not exist"):
        load_namespace_authority_context(str(missing))

    bad = tmp_path / "bad.json"
    bad.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_namespace_authority_context(bad)


def test_source_registry_is_metadata_only_never_dereferenced(tmp_path: Path):
    """source_registry may look like a path/URI; it must never be opened."""
    from code_audit.contracts.namespace_authority_context import (
        load_namespace_authority_context,
    )

    mapping = json.loads((FIXTURES / "context_valid.json").read_text(encoding="utf-8"))
    mapping["source_registry"] = "s3://fake-bucket/not-a-real-registry.json"
    ctx = load_namespace_authority_context(mapping)
    assert ctx.source_registry == "s3://fake-bucket/not-a-real-registry.json"

    findings = NamespaceAuthorityDriftAnalyzer(review_context=ctx).run(tmp_path, [])
    assert len(findings) == 1
    assert findings[0].metadata["source_registry"] == (
        "s3://fake-bucket/not-a-real-registry.json"
    )


def test_adapter_findings_are_deterministically_ordered(tmp_path: Path):
    change = CandidateChange(
        "b",
        "c",
        [
            _nc(namespace="zeta", path="z/services/api/app/zeta"),
            _nc(namespace="alpha", path="a/services/api/app/alpha"),
            _nc(namespace="mu", path="m/services/api/app/mu"),
        ],
    )
    findings = NamespaceAuthorityDriftAnalyzer(
        review_context=NamespaceAuthorityContext(
            change=change,
            topology=_binding_less(),
            source_registry="fixture:synthetic",
        )
    ).run(tmp_path, [])
    keys = [
        (f.location.path, f.location.line_start, f.metadata.get("namespace", ""), f.fingerprint)
        for f in findings
    ]
    assert keys == sorted(keys)
    assert [f.metadata["namespace"] for f in findings] == ["alpha", "mu", "zeta"]


def test_cli_namespace_authority_advisory_exit_and_errors(tmp_path: Path, capsys):
    from code_audit.__main__ import main
    from code_audit.utils.exit_codes import ExitCode

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    ctx = FIXTURES / "context_valid.json"
    flagged = FIXTURES / "context_flagged.json"

    rc = main([
        "namespace-authority",
        str(tmp_path),
        "--context",
        str(ctx),
        "--json",
    ])
    out = json.loads(capsys.readouterr().out)
    assert rc == ExitCode.SUCCESS
    assert out["advisory"] is True
    assert out["finding_count"] >= 1

    # Flagged findings remain advisory (exit 0).
    rc_flagged = main([
        "namespace-authority",
        str(tmp_path),
        "--context",
        str(flagged),
        "--json",
    ])
    flagged_out = json.loads(capsys.readouterr().out)
    assert rc_flagged == ExitCode.SUCCESS
    assert flagged_out["finding_count"] >= 1
    assert any(f.get("metadata", {}).get("flagged") for f in flagged_out["findings"])

    missing = tmp_path / "nope.json"
    rc_err = main([
        "namespace-authority",
        str(tmp_path),
        "--context",
        str(missing),
        "--json",
    ])
    assert rc_err == ExitCode.ERROR
    assert "ERROR:" in capsys.readouterr().err
