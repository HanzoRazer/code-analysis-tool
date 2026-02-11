# Fixture for mixed severity: swallowed exceptions + complex function.

import logging

logger = logging.getLogger(__name__)


def do_work(items: list[int]) -> int:
    total = 0
    for i in items:
        try:
            if i == 0:
                raise ValueError("boom")
            if i < 0:
                if i % 2 == 0:
                    total -= i
                else:
                    total += i
            elif i > 100:
                if i % 3 == 0:
                    total += i * 2
                else:
                    total += i
            else:
                total += 100 // i
        except Exception:
            pass
    return total
