def do_work(x: int) -> int:
    try:
        return 10 // x
    except Exception:
        # BAD: hides errors; should be logged or re-raised
        return 0


def do_other_work(items):
    try:
        return items[0]
    except:
        # BAD: bare except hides everything
        return None


def do_logged(data):
    import logging
    logger = logging.getLogger(__name__)
    try:
        return data["key"]
    except Exception:
        logger.error("something failed", exc_info=True)
        return None
