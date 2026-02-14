"""
Dead code hot fixture — contains all 3 dead code patterns.

Used for testing DeadCodeAnalyzer detection.
"""

# DC_UNREACHABLE_001 — code after return
def unreachable_after_return():
    return 42
    print("This will never execute")
    x = 1


# DC_UNREACHABLE_001 — code after raise
def unreachable_after_raise():
    raise ValueError("always fails")
    cleanup()  # dead code


# DC_IF_FALSE_001 — if False block
if False:
    print("This block is dead")
    DEAD_CONSTANT = 999


# DC_IF_FALSE_001 — while False block
def while_false_example():
    while False:
        print("Never loops")


# DC_ASSERT_FALSE_001 — assert False
def always_fails():
    assert False


# DC_ASSERT_FALSE_001 — assert 0 (equivalent)
def also_always_fails():
    assert 0


# DC_UNREACHABLE_001 — in a loop
def unreachable_in_loop():
    for i in range(10):
        if i == 5:
            break
            print("dead after break")
        continue
        print("dead after continue")


# Clean function for contrast
def clean_function(x, y):
    """This function has no dead code."""
    if x > y:
        return x
    return y
