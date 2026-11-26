import io
import zipfile

from secprim import safe_zip_members

MAX_MEMBER_BYTES = 5_000_000        # the largest real workbook, with headroom
MAX_ARCHIVE_BYTES = 10_000_000


def load_archive(archive_path):
    """Each annual archive holds a single workbook; hand it to the sheet reader."""
    with zipfile.ZipFile(archive_path) as zf:
        # RC-2: declared size, running total, ratio and name are checked before any read
        members = list(safe_zip_members(zf, max_member_bytes=MAX_MEMBER_BYTES,
                                        max_total_bytes=MAX_ARCHIVE_BYTES))
        return io.BytesIO(zf.read(members[0]))
