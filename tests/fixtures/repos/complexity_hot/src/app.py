# Fixture for complexity: deeply nested function with high cyclomatic complexity.


def long_and_nested(x: int) -> int:
    total = 0
    for i in range(x):
        if i % 2 == 0:
            if i % 3 == 0:
                if i % 5 == 0:
                    total += i
                else:
                    total += 1
            else:
                if i % 7 == 0:
                    total += 3
                else:
                    total += 4
        else:
            if i % 11 == 0:
                total -= 1
            else:
                total += 0
    return total
