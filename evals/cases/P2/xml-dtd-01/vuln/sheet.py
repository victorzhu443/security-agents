import xml.etree.ElementTree as ET


def shared_strings(raw: bytes) -> str:
    root = ET.fromstring(raw)            # expands whatever entities the document declares
    return "\n".join(t.text or "" for t in root.iter("t"))
