"""Negative fixture: typed parameter exists but no dispatch logic."""
from typing import Literal


def validate_format(fmt: Literal["json", "yaml"]) -> bool:
    # Just validates without dispatching on value
    return fmt is not None
    # SHOULD NOT FIRE — no dispatch found
