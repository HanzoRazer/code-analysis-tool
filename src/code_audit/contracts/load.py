"""Load and validate JSON instances against bundled or repo-layout schemas.

Usage::

    from code_audit.contracts.load import validate_instance, validate_file

    validate_instance(my_dict, "run_result.schema.json")
    validate_file(Path("out/run_result.json"), "run_result.schema.json")
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema

# ── public-facing schemas (match schemas/ at repo root) ─────────────

SCHEMA_DIR = "data/schemas"


def _schema_path(name: str) -> Path:
    """Resolve a public schema first from pip-installed package data,
    then from the repo checkout layout."""
    try:
        with resources.as_file(
            resources.files("code_audit") / SCHEMA_DIR / name
        ) as p:
            return p
    except Exception:
        # fallback: repo checkout layout  (schemas/ at project root)
        return Path(__file__).resolve().parents[3] / "schemas" / name


def load_schema(name: str) -> dict[str, Any]:
    """Load a public JSON schema by filename."""
    path = _schema_path(name)
    return json.loads(path.read_text(encoding="utf-8"))


def validate_instance(instance: Any, schema_name: str) -> None:
    """Validate *instance* against the named schema.

    Raises ``jsonschema.ValidationError`` on failure.
    """
    schema = load_schema(schema_name)
    jsonschema.validate(instance=instance, schema=schema)


def validate_file(instance_path: Path, schema_name: str) -> None:
    """Load a JSON file and validate it against the named schema."""
    instance = json.loads(instance_path.read_text(encoding="utf-8"))
    validate_instance(instance, schema_name)


# ── internal schemas (engine-layer, not user-facing) ────────────────

INTERNAL_SCHEMA_DIR = "data/internal_schemas"


def _internal_schema_path(name: str) -> Path:
    """Resolve an internal schema from package data or repo layout."""
    try:
        with resources.as_file(
            resources.files("code_audit") / INTERNAL_SCHEMA_DIR / name
        ) as p:
            return p
    except Exception:
        return (
            Path(__file__).resolve().parents[1]
            / INTERNAL_SCHEMA_DIR
            / name
        )


def load_internal_schema(name: str) -> dict[str, Any]:
    """Load an internal JSON schema by filename."""
    path = _internal_schema_path(name)
    return json.loads(path.read_text(encoding="utf-8"))


def validate_internal(instance: Any, schema_name: str) -> None:
    """Validate *instance* against an internal schema."""
    schema = load_internal_schema(schema_name)
    jsonschema.validate(instance=instance, schema=schema)
