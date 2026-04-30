"""Positive fixture: match statement with incomplete cases."""
from typing import Literal


def get_format_extension(fmt: Literal["json", "yaml", "toml"]) -> str:
    match fmt:
        case "json":
            return ".json"
        case "yaml":
            return ".yaml"
        # Missing "toml" case — no wildcard handler
    # SHOULD FIRE: SF_INCOMPLETE_DISPATCH_001
