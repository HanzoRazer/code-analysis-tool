"""Unit tests for the gate-validates-wrong-artifact detector.

Flags a validation that inspects something other than what ships: validated then
modified before return (gate before final form), or validated then abandoned
while a different artifact is returned. Precision over recall — must not fire on
``validate(input); return transform(input)``.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from code_audit.analyzers.gate_wrong_artifact import GateWrongArtifactAnalyzer
from code_audit.model import AnalyzerType, Severity


def _run(tmp_path: Path, src: str):
    p = tmp_path / "m.py"
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return GateWrongArtifactAnalyzer().run(tmp_path, [p])


# ── signal 1: validated then modified ───────────────────────────────


def test_validate_then_reassign_then_return_flagged(tmp_path):
    f = _run(tmp_path, """
        def f():
            data = build()
            validate(data)
            data = finalize(data)
            return data
    """)
    assert len(f) == 1
    assert f[0].type is AnalyzerType.GATE_WRONG_ARTIFACT
    assert f[0].metadata["rule_id"] == "GATE_WRONG_ARTIFACT_MODIFIED_001"
    assert f[0].severity is Severity.MEDIUM
    assert f[0].metadata["gate_covers_shipped_confirmed"] is False
    assert f[0].finding_id


def test_validate_then_mutate_inplace_then_return_flagged(tmp_path):
    f = _run(tmp_path, """
        def f():
            items = build()
            validate(items)
            items.append(extra)
            return items
    """)
    assert len(f) == 1
    assert f[0].metadata["rule_id"] == "GATE_WRONG_ARTIFACT_MODIFIED_001"


def test_validate_after_last_modify_not_flagged(tmp_path):
    # Correct order: modify first, then validate the final form, then ship.
    f = _run(tmp_path, """
        def f():
            data = build()
            data = finalize(data)
            validate(data)
            return data
    """)
    assert f == []


# ── signal 2: validated then abandoned ──────────────────────────────


def test_validate_one_ship_other_flagged(tmp_path):
    f = _run(tmp_path, """
        def g():
            all_contours = build_a()
            classified = build_b()
            validate(all_contours)
            return classified
    """)
    assert len(f) == 1
    assert f[0].metadata["rule_id"] == "GATE_WRONG_ARTIFACT_ABANDONED_001"
    assert f[0].metadata["validated_var"] == "all_contours"
    assert f[0].metadata["shipped_var"] == "classified"


def test_validate_input_return_derived_not_flagged(tmp_path):
    # The common CORRECT pattern: validate an input, return something derived
    # from it. Must not fire (input is a param; it's used after in transform).
    f = _run(tmp_path, """
        def h(config):
            validate(config)
            result = process(config)
            return result
    """)
    assert f == []


def test_validated_var_used_after_not_flagged(tmp_path):
    # Validated local is used later (feeds the shipped value) → not abandoned.
    f = _run(tmp_path, """
        def f():
            a = build_a()
            b = build_b()
            validate(a)
            b = combine(a, b)
            return b
    """)
    assert f == []


def test_validate_param_return_other_not_flagged(tmp_path):
    # Validated var is a PARAMETER (a precondition/guard), not a local artifact.
    f = _run(tmp_path, """
        def f(user):
            data = load()
            validate(user)
            return data
    """)
    assert f == []


def test_validate_and_return_same_var_not_flagged(tmp_path):
    # Validated exactly what is shipped, unmodified → correct.
    f = _run(tmp_path, """
        def f():
            data = build()
            validate(data)
            return data
    """)
    assert f == []


# ── validation-call shapes ──────────────────────────────────────────


def test_instance_kwarg_form_detected(tmp_path):
    f = _run(tmp_path, """
        def f():
            payload = build()
            other = build2()
            jsonschema.validate(instance=payload, schema=s)
            return other
    """)
    assert len(f) == 1
    assert f[0].metadata["validated_var"] == "payload"


def test_method_validate_form_modified(tmp_path):
    f = _run(tmp_path, """
        def f():
            doc = build()
            doc.validate()
            doc = doc.render()
            return doc
    """)
    assert len(f) == 1
    assert f[0].metadata["rule_id"] == "GATE_WRONG_ARTIFACT_MODIFIED_001"


def test_nested_function_scope_isolated(tmp_path):
    # A validated var in an inner scope must not cross into the outer analysis.
    f = _run(tmp_path, """
        def outer():
            result = build()
            def inner(x):
                validate(x)
                return x
            return result
    """)
    assert f == []


def test_clean_function_no_finding(tmp_path):
    assert _run(tmp_path, "def add(a, b):\n    return a + b\n") == []
