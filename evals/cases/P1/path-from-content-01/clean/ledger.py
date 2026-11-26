from pathlib import Path

from secprim import contained_path


class Ledger:
    def __init__(self, root):
        self.root = Path(root)

    def dest_for(self, relpath) -> Path:
        # RC-1: NUL, absolute, drive/UNC forms and any '..' route that resolves
        # outside the root raise MalformedInput; otherwise the unresolved join.
        return contained_path(self.root, relpath)


dest_for = Ledger("/srv/hub/courses/cs-3110").dest_for
