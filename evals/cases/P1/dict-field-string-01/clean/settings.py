from secprim import as_dict


def apply(payload):
    payload = as_dict(payload, "payload")
    controls = as_dict(payload.get("controls"), "payload.controls", optional=True)
    return {name: bool(cfg) for name, cfg in controls.items()}
