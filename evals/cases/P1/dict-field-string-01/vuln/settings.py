from secprim import MalformedInput


def apply(payload):
    """Per-widget controls: {"controls": {"volume": {...}, ...}}. The envelope is
    checked; the controls object is assumed."""
    if not isinstance(payload, dict):
        raise MalformedInput("payload: expected an object")
    controls = payload.get("controls") or {}
    return {name: bool(cfg) for name, cfg in controls.items()}    # a str/list/int has no .items
