"""Strict serialized review-context loader for namespace-authority analysis."""
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping

from code_audit.analyzers.namespace_authority_engine import (
    CandidateChange,
    NamespaceChange,
)
from code_audit.contracts.load import validate_instance

if TYPE_CHECKING:
    from code_audit.analyzers.namespace_authority_drift import NamespaceAuthorityContext

_SCHEMA = "namespace_authority_context.schema.json"


def _read_context_json(path: Path) -> Any:
    """Read a context file from disk. ``source_registry`` is never opened here."""
    if not path.is_file():
        raise FileNotFoundError(
            "namespace_authority_context path does not exist or is not a file: "
            f"{path}"
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"namespace_authority_context is not valid JSON: {path}"
        ) from exc


def load_namespace_authority_context(
    source: Mapping[str, Any] | str | Path,
) -> NamespaceAuthorityContext:
    """Load a v1 JSON context without inferring authority.

    Accepted forms:
    - a JSON-serializable ``namespace_authority_context_v1`` mapping
    - a filesystem path (``Path`` or path ``str``) to a JSON file

    Raw JSON string payloads are **not** accepted: a ``str`` is always treated
    as a path string. Mapping/path inputs are schema-validated before any
    engine objects are constructed. ``topology`` stays embedded data;
    ``source_registry`` is attribution metadata only and is never dereferenced.
    """
    if isinstance(source, Path):
        data = _read_context_json(source)
    elif isinstance(source, str):
        # Path string only — reject raw JSON blobs that callers might pass as str.
        stripped = source.lstrip()
        if stripped.startswith(("{", "[")):
            raise TypeError(
                "namespace_authority_context str must be a filesystem path to a "
                "JSON file, not a raw JSON string; pass a mapping or a Path/"
                "path string"
            )
        data = _read_context_json(Path(source))
    elif isinstance(source, Mapping):
        data = dict(source)
    else:
        raise TypeError(
            "namespace_authority_context must be a mapping or JSON path, "
            f"got {type(source).__name__}"
        )

    validate_instance(data, _SCHEMA)

    change_data = data["change"]
    namespace_changes = [
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
        for item in change_data["namespace_changes"]
    ]

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
