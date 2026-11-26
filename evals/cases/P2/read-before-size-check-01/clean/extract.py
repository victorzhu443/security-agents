import zipfile

from secprim import TooLarge

MAX_XML_BYTES = 5_000_000      # a real course workbook's sharedStrings is kilobytes


def xlsx_text(p):
    """Shared-strings part of an attacker-postable .xlsx, for the text index."""
    with zipfile.ZipFile(p) as z:
        try:
            info = z.getinfo("xl/sharedStrings.xml")
        except KeyError:
            return ""
        # Declared size BEFORE reading (RC-2): zipfile stops at the declared size,
        # so nothing past the ceiling is ever decompressed.
        if info.file_size > MAX_XML_BYTES:
            raise TooLarge(f"sharedStrings declares {info.file_size} bytes")
        raw = z.read(info)
    return raw.decode("utf-8", "replace")
