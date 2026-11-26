from secprim import as_dict, as_list, MalformedInput


def parse(payload):
    """Same parser; every node is shape-checked, failures are MalformedInput."""
    payload = as_dict(payload, "payload")
    options = as_list(payload.get("options") or [], "payload.options")
    return [str(as_dict(o, "payload.options[]").get("label", "")) for o in options]
