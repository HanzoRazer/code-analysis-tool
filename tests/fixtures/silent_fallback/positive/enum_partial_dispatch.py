"""Positive fixture: Enum type with incomplete dispatch and silent default."""
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
    return "refined_output"  # Silent fallback for CAM_READY_R2000
    # SHOULD FIRE: SF_INCOMPLETE_DISPATCH_001
