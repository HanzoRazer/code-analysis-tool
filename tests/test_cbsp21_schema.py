import json
from pathlib import Path

import jsonschema

REPO_ROOT = Path(__file__).resolve().parents[1]

def test_cbsp21_example_validates_against_schema():
    schema_path = REPO_ROOT / "cbsp21" / "patch_input.schema.json"
    example_path = REPO_ROOT / "cbsp21" / "patch_input.json.example"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    example = json.loads(example_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=example, schema=schema)

def test_cbsp21_template_has_required_top_level_keys():
    template_path = REPO_ROOT / "cbsp21" / "patch_input.template.json"
    template = json.loads(template_path.read_text(encoding="utf-8"))

    for k in ["schema_version", "scope", "diff_range", "diff_articulation", "verification"]:
        assert k in template, f"Missing key in template: {k}"
