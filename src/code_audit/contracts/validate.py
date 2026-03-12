from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


class ContractValidationError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _load_finding_schema() -> dict[str, Any]:
    # repo_root/schemas/finding.schema.json
    repo_root = Path(__file__).resolve().parents[3]
    schema_path = repo_root / "schemas" / "finding.schema.json"
    if not schema_path.exists():
        raise ContractValidationError(f"Missing finding schema: {schema_path}")
    return json.loads(schema_path.read_text(encoding="utf-8"))


def validate_finding(finding: dict[str, Any]) -> None:
    """Strict contract validation for findings.

    Raises ContractValidationError if invalid.
    """
    try:
        import jsonschema  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise ContractValidationError(
            "jsonschema is required for strict finding validation. "
            "Install the runtime dependency or disable the feature explicitly (not supported here)."
        ) from exc

    schema = _load_finding_schema()
    try:
        jsonschema.validate(instance=finding, schema=schema)
    except Exception as exc:
        raise ContractValidationError(f"Finding failed schema validation: {exc}") from exc
