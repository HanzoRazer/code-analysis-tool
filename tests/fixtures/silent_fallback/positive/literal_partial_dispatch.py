"""Positive fixture: Literal type with incomplete dispatch."""
from typing import Literal


def compute_temperament(t: Literal["12-TET", "19-TET", "pythagorean"]) -> list[float]:
    if t == "12-TET":
        return [0.0, 100.0, 200.0]
    elif t == "19-TET":
        return [0.0, 63.16, 126.32]
    # No handler for "pythagorean" — falls through, returns None implicitly
    # SHOULD FIRE: SF_INCOMPLETE_DISPATCH_001
