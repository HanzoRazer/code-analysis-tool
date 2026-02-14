# Fixture: various exception-handling anti-patterns for code-audit scanning.

import logging
import os

logger = logging.getLogger(__name__)

_GLOBAL_CACHE: dict[str, object] = {}


def swallowed_exception(path: str) -> str | None:
    """Bare except that silently swallows."""
    try:
        with open(path) as f:
            return f.read()
    except:
        pass
    return None


def broad_except_logging(data: list[int]) -> int:
    """Catches Exception -- too broad."""
    total = 0
    for item in data:
        try:
            total += 100 // item
        except Exception:
            logger.warning("skipped %s", item)
    return total


def nested_try(value: str) -> int:
    """Nested try blocks with mixed handling."""
    try:
        n = int(value)
        try:
            return 1000 // n
        except ZeroDivisionError:
            return -1
    except Exception:
        pass
    return 0


def complex_branching(items: list[int]) -> int:
    """High cyclomatic complexity with exception paths."""
    result = 0
    for i in items:
        try:
            if i < 0:
                if i % 2 == 0:
                    result -= i
                elif i % 3 == 0:
                    result += i * 2
                else:
                    result += abs(i)
            elif i == 0:
                raise ValueError("zero")
            elif i > 100:
                if i % 5 == 0:
                    result += i // 5
                else:
                    result += i
            else:
                result += 100 // i
        except Exception:
            pass
    return result


def mutate_global(key: str, value: object) -> None:
    """Global state mutation."""
    _GLOBAL_CACHE[key] = value


def read_global(key: str) -> object | None:
    """Global state read."""
    return _GLOBAL_CACHE.get(key)


def unreachable_after_return(x: int) -> str:
    """Dead code after early return."""
    if x > 0:
        return "positive"
    return "non-positive"
    print("this is unreachable")  # noqa: T201


def _unused_helper() -> None:
    """Never called -- dead code."""
    os.getenv("UNUSED_VAR")
