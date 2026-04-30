"""Negative fixture: all Literal values handled explicitly."""
from typing import Literal


def compute_temperament(t: Literal["12-TET", "19-TET", "pythagorean"]) -> list[float]:
    if t == "12-TET":
        return [0.0, 100.0, 200.0]
    elif t == "19-TET":
        return [0.0, 63.16, 126.32]
    elif t == "pythagorean":
        return [0.0, 90.22, 203.91]
    else:
        raise ValueError(f"unsupported temperament: {t}")
    # SHOULD NOT FIRE — all values covered with explicit error fallback
