"""Namespace-authority drift adapter for the code-analysis suite (advisory v1).

Wraps the vendored Git-independent engine (``namespace_authority_engine``) and
normalizes ``DriftFinding`` values into suite ``Finding`` objects.

Silent without review context — ordinary file sweeps do not invent a candidate
change or authority topology. Direct ``NamespaceAuthorityContext`` objects are
accepted; serialized mapping/path activation is parsed by the strict v1 loader.

Provenance pin: luthiers-toolbox@14c15afca6c1e9c029a221ef97d2c46613dfb717 (#273).
NAD-PORT-001 COMPLETE — do not use d796cf95 / e25c7390 / a368652f.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from code_audit.analyzers.namespace_authority_engine import (
    FLAGGED_VERDICTS,
    AuthorityTopology,
    CandidateChange,
    DriftFinding,
    NativeSeverity,
    Verdict,
    analyze_namespace_authority_drift,
)
from code_audit.model import AnalyzerType, Severity
from code_audit.model.finding import Finding, Location, make_fingerprint

_RULE_ID = "NAMESPACE_AUTHORITY_DRIFT_001"
_PROVENANCE = "luthiers-toolbox@14c15afca6c1e9c029a221ef97d2c46613dfb717"

_SUITE_SEVERITY = {
    NativeSeverity.INFORMATIONAL: Severity.INFO,
    NativeSeverity.ADVISORY: Severity.LOW,
    NativeSeverity.WARNING: Severity.LOW,
    NativeSeverity.BLOCKING: Severity.LOW,
}


@dataclass(frozen=True, slots=True)
class NamespaceAuthorityContext:
    """Activates namespace-authority adjudication inside a scan."""

    change: CandidateChange
    topology: AuthorityTopology | dict[str, Any] | Path
    namespace_bindings: dict[str, Any] | None = None
    source_registry: str = "injected"


def _normalize(drift: DriftFinding, *, source_registry: str, base_ref: str, candidate_ref: str) -> Finding:
    flagged = drift.verdict in FLAGGED_VERDICTS
    rel = drift.path.replace("\\", "/")
    snippet = drift.evidence[:200]
    fingerprint = make_fingerprint(_RULE_ID, rel, drift.namespace, drift.verdict.value)
    message = (
        f"Namespace '{drift.namespace}' — {drift.verdict.value}: {drift.evidence} "
        f"Recommended next action: governance review (do not invent a binding here)."
    )
    return Finding(
        finding_id=fingerprint,
        type=AnalyzerType.NAMESPACE_AUTHORITY_DRIFT,
        severity=_SUITE_SEVERITY[drift.severity],
        confidence=0.7 if flagged else (0.55 if drift.verdict is Verdict.INSUFFICIENT_EVIDENCE else 0.5),
        message=message,
        location=Location(path=rel, line_start=1, line_end=1),
        fingerprint=fingerprint,
        snippet=snippet,
        metadata={
            "rule_id": _RULE_ID,
            "detector_id": "namespace_authority_drift",
            "verdict": drift.verdict.value,
            "severity_native": drift.severity.value,
            "flagged": flagged,
            "namespace": drift.namespace,
            "path": rel,
            "base_ref": base_ref,
            "candidate_ref": candidate_ref,
            "evidence": drift.evidence,
            "source_registry": source_registry,
            "provenance": _PROVENANCE,
            "posture": "advisory",
        },
    )


class NamespaceAuthorityDriftAnalyzer:
    """Advisory adapter: declared-authority drift only; silent without context."""

    id: str = "namespace_authority_drift"
    version: str = "0.2.0"

    def __init__(
        self,
        review_context: NamespaceAuthorityContext | dict[str, Any] | str | Path | None = None,
    ) -> None:
        self._ctx = self._coerce_context(review_context)

    @staticmethod
    def _coerce_context(
        review_context: NamespaceAuthorityContext | dict[str, Any] | str | Path | None,
    ) -> NamespaceAuthorityContext | None:
        if review_context is None:
            return None
        if isinstance(review_context, NamespaceAuthorityContext):
            return review_context

        # Serialized inputs have exactly one trust boundary: the strict loader.
        # In particular, the legacy object-bearing dict form is intentionally
        # rejected by schema validation instead of bypassing the JSON contract.
        if isinstance(review_context, (dict, str, Path)):
            from code_audit.contracts.namespace_authority_context import (
                load_namespace_authority_context,
            )
            return load_namespace_authority_context(review_context)

        raise TypeError(
            "review_context must be NamespaceAuthorityContext | mapping | JSON path | None, "
            f"got {type(review_context).__name__}"
        )

    def run(self, root: Path, files: list[Path]) -> list[Finding]:
        del root, files
        ctx = self._ctx
        if ctx is None:
            return []

        drifts = analyze_namespace_authority_drift(
            ctx.change,
            ctx.topology,
            namespace_bindings=ctx.namespace_bindings,
        )
        findings = [
            _normalize(
                d,
                source_registry=ctx.source_registry,
                base_ref=ctx.change.base_ref,
                candidate_ref=ctx.change.candidate_ref,
            )
            for d in drifts
        ]
        return sorted(
            findings,
            key=lambda f: (
                f.location.path,
                f.location.line_start,
                f.metadata.get("namespace", ""),
                f.fingerprint,
            ),
        )
