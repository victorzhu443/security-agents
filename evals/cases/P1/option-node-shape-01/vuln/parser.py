def parse(payload):
    """Hostile DOM extract -> option labels. Validates the list, not the nodes."""
    if not isinstance(payload, dict):
        return []
    options = payload.get("options") or []
    if not isinstance(options, list):
        return []
    return [str(o.get("label", "")) for o in options]      # o may be a str/int/None
