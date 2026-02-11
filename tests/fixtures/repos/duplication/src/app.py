# Fixture for duplication: two structurally identical functions.
#
# process_users and process_orders differ only in variable names and
# string/numeric literals — the DuplicationAnalyzer should flag them
# as structural clones.


def process_users(users):
    """Filter and transform user records."""
    result = []
    for user in users:
        if user.get("active"):
            name = user.get("name", "unknown")
            score = user.get("score", 0)
            if score > 50:
                result.append({"name": name, "tier": "gold"})
            else:
                result.append({"name": name, "tier": "silver"})
    return result


def process_orders(orders):
    """Filter and transform order records."""
    result = []
    for order in orders:
        if order.get("confirmed"):
            ref = order.get("ref", "unknown")
            total = order.get("total", 0)
            if total > 50:
                result.append({"ref": ref, "tier": "gold"})
            else:
                result.append({"ref": ref, "tier": "silver"})
    return result
