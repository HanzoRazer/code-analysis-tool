from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCHEMAS = [
    (ROOT / "schemas" / "release_bom.schema.json", r"^release_bom_schema_v\d+$"),
    (ROOT / "schemas" / "release_audit_failure.schema.json", r"^release_audit_failure_schema_v\d+$"),
    (ROOT / "schemas" / "release_bom_consistency_result.schema.json", r"^release_bom_consistency_result_schema_v\d+$"),
]


def test_release_schema_version_naming_contract() -> None:
    """
    Each release-related schema must have schema_version matching a naming pattern,
    and $id must equal schema_version (identity coherence).
    """
    for path, pattern in SCHEMAS:
        if not path.exists():
            continue  # not yet created; skip
        obj = json.loads(path.read_text(encoding="utf-8"))
        sv = obj.get("schema_version")
        sid = obj.get("$id")
        assert isinstance(sv, str) and sv, f"{path.name}: missing schema_version"
        assert re.match(pattern, sv), f"{path.name}: schema_version {sv!r} does not match {pattern}"
        assert sv == sid, (
            f"{path.name}: schema_version ({sv!r}) must equal $id ({sid!r}) for identity coherence"
        )
