"""Public activation helpers for serialized namespace-authority review context."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from code_audit.analyzers.namespace_authority_drift import (
    NamespaceAuthorityContext,
    NamespaceAuthorityDriftAnalyzer,
)
from code_audit.model.finding import Finding


def check_namespace_authority(
    root: str | Path,
    *,
    context: NamespaceAuthorityContext | Mapping[str, Any] | str | Path,
) -> list[Finding]:
    """Run only the advisory namespace-authority analyzer.

    Findings are advisory and therefore do not imply a failing process status.
    Serialized mapping / path-string / ``Path`` inputs pass through the
    analyzer's strict v1 loader. A ``str`` context is a filesystem path only
    (raw JSON string payloads are rejected).
    """
    root_p = Path(root).resolve()
    if not root_p.is_dir():
        raise FileNotFoundError(
            f"check_namespace_authority: root is not a directory: {root_p}"
        )
    analyzer = NamespaceAuthorityDriftAnalyzer(review_context=context)
    return analyzer.run(root_p, [])
