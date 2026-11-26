from secprim import safe_xml_fromstring


def shared_strings(raw: bytes) -> str:
    root = safe_xml_fromstring(raw, max_bytes=5_000_000)   # no DTD, no entities, capped
    return "\n".join(t.text or "" for t in root.iter("t"))
