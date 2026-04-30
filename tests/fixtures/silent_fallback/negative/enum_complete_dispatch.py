"""Negative fixture: all Enum members handled explicitly."""
from enum import Enum


class Mode(Enum):
    REFINED = "refined"
    ENHANCED = "enhanced"
    CAM_READY_R2000 = "cam_ready_r2000"


def process(mode: Mode) -> str:
    if mode == Mode.REFINED:
        return "refined_output"
    elif mode == Mode.ENHANCED:
        return "enhanced_output"
    elif mode == Mode.CAM_READY_R2000:
        return "cam_ready_output"
    # SHOULD NOT FIRE — all enum members handled
