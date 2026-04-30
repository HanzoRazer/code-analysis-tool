"""Negative fixture: generic str parameter — can't enumerate value space."""


def compute(t: str) -> list[float]:
    if t == "12-TET":
        return [0.0, 100.0, 200.0]
    return [0.0, 100.0, 200.0]  # Default
    # SHOULD NOT FIRE — generic str, can't enumerate possible values
