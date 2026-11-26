import zipfile

MAX_XML_BYTES = 5_000_000      # a real course workbook's sharedStrings is kilobytes


def xlsx_text(p):
    """Shared-strings part of an attacker-postable .xlsx, for the text index."""
    with zipfile.ZipFile(p) as z:
        try:
            raw = z.read("xl/sharedStrings.xml")      # decompresses the whole part ...
        except KeyError:
            return ""
        if len(raw) > MAX_XML_BYTES:                   # ... and only then looks at its size
            return ""
    return raw.decode("utf-8", "replace")
