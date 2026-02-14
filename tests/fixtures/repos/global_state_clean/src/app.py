"""A module with no global state issues — clean baseline."""

THRESHOLD = 100  # immutable int
APP_NAME = "my-app"  # immutable str
COORDS = (1, 2, 3)  # immutable tuple


def greet(name: str, prefix: str = "Hello") -> str:
    return f"{prefix}, {name}!"


def add(a: int, b: int, offset: int = 0) -> int:
    return a + b + offset
