# Fixture for safety fences: bare except + missing @safety_critical.
#
# This file exercises the SafetyFenceAnalyzer:
#  1. generate_gcode() lacks @safety_critical → FENCE-SAFETY-DECORATOR
#  2. The bare except inside it → FENCE-BARE-EXCEPT


def generate_gcode(toolpath):
    """Convert toolpath to G-code — safety-critical but missing decorator."""
    try:
        commands = []
        for point in toolpath:
            commands.append(f"G01 X{point[0]} Y{point[1]}")
        return "\n".join(commands)
    except:
        return ""
