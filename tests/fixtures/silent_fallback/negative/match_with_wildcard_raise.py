"""Negative fixture: match statement with wildcard case that raises."""
from typing import Literal


def get_format_extension(fmt: Literal["json", "yaml", "toml"]) -> str:
    match fmt:
        case "json":
            return ".json"
        case "yaml":
            return ".yaml"
        case _:
            raise ValueError(f"unsupported format: {fmt}")
    # SHOULD NOT FIRE — wildcard case raises
