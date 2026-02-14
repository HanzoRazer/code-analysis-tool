"""
Dead code clean fixture — no dead code patterns.

Used for testing that DeadCodeAnalyzer produces no false positives.
"""


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


def greet(name: str) -> str:
    """Generate a greeting."""
    if not name:
        return "Hello, stranger!"
    return f"Hello, {name}!"


def process_items(items: list) -> list:
    """Process items with early return for empty list."""
    if not items:
        return []

    result = []
    for item in items:
        if item is None:
            continue
        result.append(item * 2)
    return result


def safe_divide(a: float, b: float) -> float | None:
    """Divide with guard clause."""
    if b == 0:
        return None
    return a / b


class Calculator:
    """Simple calculator class."""

    def __init__(self, initial: int = 0):
        self.value = initial

    def add(self, x: int) -> int:
        self.value += x
        return self.value

    def reset(self) -> None:
        self.value = 0


# Module-level constant (immutable, not dead code)
VERSION = "1.0.0"
MAX_RETRIES = 3


# Conditional that uses a variable (not literal False)
DEBUG = False
if DEBUG:
    print("Debug mode enabled")


# Assert with a condition (not literal False)
def validate(x: int) -> None:
    assert x >= 0, "x must be non-negative"
