import io
import zipfile


def load_archive(archive_path):
    """Each annual archive holds a single workbook; hand it to the sheet reader."""
    with zipfile.ZipFile(archive_path) as zf:
        workbook_name = zf.namelist()[0]
        return io.BytesIO(zf.read(workbook_name))        # whatever size the archive declares
