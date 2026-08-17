"""Namespace / authority drift analysis engine (Git-independent).

Ported from HanzoRazer/luthiers-toolbox@14c15afca6c1e9c029a221ef97d2c46613dfb717.
Behavioral provenance pin only; this copy is maintained by code-analysis-tool.

NAD-PORT-001 COMPLETE / VERIFIED ON main — canonical suite pin is that SHA
(#273 squash merge; includes #272 adapter hardening). Do not use d796cf95,
e25c7390, or a368652f as provenance.

Vendors the candidate-change model + authority analysis engine only.
Does **not** vendor the Luthiers git/ref adapter, CLI, repository-specific
authority declarations, namespace bindings, or blocking policy.

Core boundary:
  THE DETECTOR MAY CONSUME AUTHORITY. IT MAY NOT CREATE AUTHORITY.
  Missing namespace→domain bindings yield INSUFFICIENT_EVIDENCE — never a
  guessed domain mapping (no inference from names, paths, or keywords).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Tuple, Union


class NativeSeverity(str, Enum):
    """Detector-native severity vocabulary (advisory v1; independent of suite Severity)."""

    INFORMATIONAL = "informational"
    ADVISORY = "advisory"
    WARNING = "warning"
    BLOCKING = "blocking"


# Neutral defaults — suite callers inject topology; do not assume a Luthiers checkout.
_DEFAULT_REPO_ROOT = Path(".")
_DEFAULT_AUTHORITY_REGISTRY = Path("authority_chain_registry.json")
_DEFAULT_AUTHORITY_ARTIFACT_PATHS: FrozenSet[str] = frozenset({
    "contracts/schema_registry.json",
    "docs/governance/ontology/authority_chain_registry.json",
    "docs/governance/ontology/semantic_registry.json",
    "docs/governance/governance_manifest.json",
})
_DEFAULT_CODE_ROOTS = ("services/api/app/", "services/")
_DEFAULT_NON_CODE_HINTS = ("docs/", "tests/", "test/", "examples/", "presets/", ".github/")


@dataclass(frozen=True)
class DetectorConfig:
    """Injectable layout facts for registry loading / future git adapters.

    Path-classification facts only — not authority. The analysis engine never
    invents namespace→domain bindings from these paths.
    """

    repo_root: Path = _DEFAULT_REPO_ROOT
    code_roots: Tuple[str, ...] = _DEFAULT_CODE_ROOTS
    non_code_hints: Tuple[str, ...] = _DEFAULT_NON_CODE_HINTS
    authority_artifact_paths: FrozenSet[str] = _DEFAULT_AUTHORITY_ARTIFACT_PATHS
    authority_registry_path: Path = _DEFAULT_AUTHORITY_REGISTRY

    @classmethod
    def luthiers_defaults(cls, repo_root: Path) -> "DetectorConfig":
        """Luthiers-Toolbox layout under an explicit checkout root."""
        root = Path(repo_root)
        return cls(
            repo_root=root,
            authority_registry_path=(
                root / "docs" / "governance" / "ontology" / "authority_chain_registry.json"
            ),
        )


DEFAULT_CONFIG = DetectorConfig()


class Verdict(str, Enum):
    NO_AUTHORITY_IMPACT = "NO_AUTHORITY_IMPACT"
    DECLARED_EXTENSION = "DECLARED_EXTENSION"
    NOVEL_VALID = "NOVEL_VALID"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    DUPLICATE_AUTHORITY = "DUPLICATE_AUTHORITY"
    PARALLEL_AUTHORITY = "PARALLEL_AUTHORITY"
    OBSOLETE_AUTHORITY = "OBSOLETE_AUTHORITY"
    AUTHORITY_BYPASS = "AUTHORITY_BYPASS"


FLAGGED_VERDICTS = frozenset({
    Verdict.DUPLICATE_AUTHORITY,
    Verdict.PARALLEL_AUTHORITY,
    Verdict.OBSOLETE_AUTHORITY,
    Verdict.AUTHORITY_BYPASS,
})

_NATIVE_SEVERITY = {
    Verdict.NO_AUTHORITY_IMPACT: NativeSeverity.INFORMATIONAL,
    Verdict.DECLARED_EXTENSION: NativeSeverity.INFORMATIONAL,
    Verdict.NOVEL_VALID: NativeSeverity.INFORMATIONAL,
    Verdict.INSUFFICIENT_EVIDENCE: NativeSeverity.ADVISORY,
    Verdict.DUPLICATE_AUTHORITY: NativeSeverity.WARNING,
    Verdict.PARALLEL_AUTHORITY: NativeSeverity.WARNING,
    Verdict.OBSOLETE_AUTHORITY: NativeSeverity.WARNING,
    Verdict.AUTHORITY_BYPASS: NativeSeverity.WARNING,
}


@dataclass
class NamespaceChange:
    """One namespace-level change. Authority-derived fields are binding-sourced only."""

    namespace: str
    path: str
    change: str  # "added" | "removed" | "modified"
    is_code_namespace: bool = True
    touches_authority_artifacts: Tuple[str, ...] = ()
    declared_domain: Optional[str] = None
    declared_concept: Optional[str] = None
    introduces_parallel_registry: bool = False
    violates_invariant: Optional[str] = None
    restores_superseded: bool = False


@dataclass
class CandidateChange:
    base_ref: str
    candidate_ref: str
    namespace_changes: List[NamespaceChange] = field(default_factory=list)


@dataclass
class DriftFinding:
    namespace: str
    path: str
    verdict: Verdict
    severity: NativeSeverity
    evidence: str

    def to_dict(self) -> Dict:
        return {
            "namespace": self.namespace,
            "path": self.path,
            "verdict": self.verdict.value,
            "severity": self.severity.value,
            "flagged": self.verdict in FLAGGED_VERDICTS,
            "evidence": self.evidence,
        }


class AuthorityTopology:
    """Reads DECLARED authority; never invents it."""

    def __init__(self, registry: Dict, namespace_bindings: Optional[Dict] = None):
        self.registry = registry
        self.domain_ownership: Dict = registry.get("domain_ownership", {}) or {}
        self.chains: Dict = registry.get("chains", {}) or {}
        self.namespace_bindings: Dict = (
            namespace_bindings
            if namespace_bindings is not None
            else registry.get("namespace_bindings", {}) or {}
        )

    @classmethod
    def load(
        cls,
        registry_path: Optional[Path] = None,
        *,
        config: Optional[DetectorConfig] = None,
    ) -> "AuthorityTopology":
        cfg = config or DEFAULT_CONFIG
        path = registry_path if registry_path is not None else cfg.authority_registry_path
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data)

    def operational_owners(self, domain: str) -> set:
        d = self.domain_ownership.get(domain, {}) or {}
        owners = set(d.get("operational_owners", []) or [])
        if d.get("canonical_owner"):
            owners.add(d["canonical_owner"])
        return owners

    def resolve(self, nc: NamespaceChange) -> Optional[Tuple[str, str]]:
        """Return (domain, concept) IFF a DECLARED binding exists; else None."""
        if nc.declared_domain and nc.declared_domain in self.domain_ownership:
            return (nc.declared_domain, nc.declared_concept or nc.namespace)
        b = self.namespace_bindings.get(nc.namespace)
        if isinstance(b, dict) and b.get("domain") in self.domain_ownership:
            return (b["domain"], b.get("concept", nc.namespace))
        return None


def adjudicate(nc: NamespaceChange, topo: AuthorityTopology) -> DriftFinding:
    """Deterministic verdict for one namespace change. Every verdict carries evidence."""

    def finding(v: Verdict, ev: str) -> DriftFinding:
        return DriftFinding(nc.namespace, nc.path, v, _NATIVE_SEVERITY[v], ev)

    if not nc.is_code_namespace:
        if nc.touches_authority_artifacts:
            artifacts = ", ".join(sorted(nc.touches_authority_artifacts))
            return finding(
                Verdict.NO_AUTHORITY_IMPACT,
                (
                    "change introduces no code namespace (docs/tests/config only), but "
                    f"it MODIFIES declared authority artifact(s) "
                    f"{artifacts} - review the topology change "
                    f"itself; this tool adjudicates candidate namespaces against the "
                    f"topology and does not adjudicate edits to the topology"
                ),
            )
        return finding(
            Verdict.NO_AUTHORITY_IMPACT,
            "change introduces no code namespace (docs/tests/config only)",
        )

    binding = topo.resolve(nc)
    if binding is None:
        art = (
            f"; touches authority artifact(s) "
            f"{', '.join(sorted(nc.touches_authority_artifacts))}"
            if nc.touches_authority_artifacts
            else ""
        )
        return finding(
            Verdict.INSUFFICIENT_EVIDENCE,
            (
                f"code namespace '{nc.namespace}' has no declared namespace->domain "
                f"binding in the authority topology - cannot adjudicate ownership "
                f"(binding-layer gap){art}. This is evidence the topology is "
                f"incomplete, not a defect in the change."
            ),
        )

    domain, concept = binding
    if nc.violates_invariant:
        return finding(
            Verdict.AUTHORITY_BYPASS,
            f"change in domain '{domain}' violates a declared chain invariant: "
            f"{nc.violates_invariant!r}",
        )
    if nc.restores_superseded:
        return finding(
            Verdict.OBSOLETE_AUTHORITY,
            f"restores a namespace declared superseded within domain '{domain}'",
        )
    if nc.introduces_parallel_registry:
        return finding(
            Verdict.PARALLEL_AUTHORITY,
            f"introduces an independent registry/contract for domain '{domain}', "
            f"which already has a declared authority",
        )

    owners = topo.operational_owners(domain)
    if concept in owners:
        return finding(
            Verdict.DECLARED_EXTENSION,
            f"'{concept}' is a declared operational owner of domain '{domain}' "
            f"({sorted(owners)}) - recognized authority participant, not drift",
        )
    if owners:
        return finding(
            Verdict.DUPLICATE_AUTHORITY,
            f"'{concept}' claims domain '{domain}' already owned by {sorted(owners)} "
            f"and is not a declared owner",
        )
    return finding(
        Verdict.NOVEL_VALID,
        f"'{concept}' introduces domain '{domain}' with no existing declared owner "
        f"and no conflicting authority",
    )


def analyze(change: CandidateChange, topo: AuthorityTopology) -> List[DriftFinding]:
    return [adjudicate(nc, topo) for nc in change.namespace_changes]


def analyze_namespace_authority_drift(
    change: CandidateChange,
    topology: Union[AuthorityTopology, Dict, Path],
    *,
    namespace_bindings: Optional[Dict] = None,
) -> List[DriftFinding]:
    """Portable engine entrypoint. Does not invent authority. Does not touch git."""
    if isinstance(topology, AuthorityTopology):
        topo = topology
    elif isinstance(topology, Path):
        data = json.loads(topology.read_text(encoding="utf-8"))
        topo = AuthorityTopology(data, namespace_bindings=namespace_bindings)
    elif isinstance(topology, dict):
        topo = AuthorityTopology(topology, namespace_bindings=namespace_bindings)
    else:
        raise TypeError(
            "topology must be AuthorityTopology | dict | Path, "
            f"got {type(topology).__name__}"
        )
    return analyze(change, topo)
