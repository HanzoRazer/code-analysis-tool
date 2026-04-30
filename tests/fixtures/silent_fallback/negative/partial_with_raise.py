"""Negative fixture: partial dispatch but raises on default."""
from enum import Enum


class Mode(Enum):
    REFINED = "refined"
    ENHANCED = "enhanced"
    CAM_READY_R2000 = "cam_ready_r2000"


def process(mode: Mode) -> str:
    if mode == Mode.REFINED:
        return "refined_output"
    if mode == Mode.ENHANCED:
        return "enhanced_output"
    raise NotImplementedError(f"mode not implemented: {mode}")
    # SHOULD NOT FIRE — explicit raise for unhandled cases
