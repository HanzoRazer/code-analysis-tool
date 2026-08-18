"""Strict serialized review-context loader for namespace-authority analysis."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from code_audit.analyzers.namespace_authority_engine import (
    CandidateChange,
    NamespaceChange,
)
from code_audit.contracts.load import validate_instance

_SCHEMA = "namespace_authority_context.schema.json"


def load_namespace_authority_context(
    source: Mapping[str, Any] | str | Path,
):
    """Load a v1 JSON context without inferring authority.

    Mapping/path inputs are schema-validated before any engine objects are
    constructed. ``topology`` stays embedded data; ``source_registry`` is
    attribution metadata only and is never dereferenced.
    """
    if isinstance(source, (str, Path)):
        path = Path(source)
        data = json.loads(path.read_text(encoding="utf-8"))
    elif isinstance(source, Mapping):
        data = dict(source)
    else:
        raise TypeError(
            "namespace_authority_context must be a mapping or JSON path, "
            f"got {type(source).__name__}"
        )

    validate_instance(data, _SCHEMA)

    change_data = data["change"]
    namespace_changes = []
    for item in change_data["namespace_changes"]:
        namespace_changes.append(
            NamespaceChange(
                namespace=item["namespace"],
                path=item["path"],
                change=item["change"],
                is_code_namespace=item.get("is_code_namespace", True),
                touches_authority_artifacts=tuple(item.get("touches_authority_artifacts", ())),
                declared_domain=item.get("declared_domain"),
                declared_concept=item.get("declared_concept"),
                introduces_parallel_registry=item.get("introduces_parallel_registry", False),
                violates_invariant=item.get("violates_invariant"),
                restores_superseded=item.get("restores_superseded", False),
            )
        )

    change = CandidateChange(
        base_ref=change_data["base_ref"],
        candidate_ref=change_data["candidate_ref"],
        namespace_changes=namespace_changes,
    )

    # Local import avoids a module cycle: the adapter imports engine models.
    from code_audit.analyzers.namespace_authority_drift import NamespaceAuthorityContext

    return NamespaceAuthorityContext(
        change=change,
        topology=data["topology"],
        namespace_bindings=data.get("namespace_bindings"),
        source_registry=data.get("source_registry", "injected"),
    )
