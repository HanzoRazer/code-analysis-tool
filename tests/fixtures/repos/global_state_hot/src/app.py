CACHE = {}
NAMES = []
FLAGS = set()


def add_name(x, seen=set()):
    global CACHE
    CACHE["last"] = x
    seen.add(x)
    return seen
