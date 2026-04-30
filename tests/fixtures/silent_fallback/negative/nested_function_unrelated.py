"""Negative fixture: nested function with different parameter."""
from typing import Literal


def outer(mode: Literal["a", "b", "c"]) -> str:
    # Dispatch on all values
    if mode == "a":
        return "a_result"
    elif mode == "b":
        return "b_result"
    elif mode == "c":
        return "c_result"

    def inner(other: str) -> str:
        # Different parameter, not related to outer's typed param
        return other.upper()

    return inner(mode)
    # SHOULD NOT FIRE — outer handles all values, inner has different param
