from pathlib import Path


class Ledger:
    """Every item a collector saves goes through put(); the destination is built
    from the filename the upstream system reported."""

    def __init__(self, root):
        self.root = Path(root)

    def dest_for(self, relpath) -> Path:
        return self.root / relpath        # absolute replaces root; '..' walks out of it


dest_for = Ledger("/srv/hub/courses/cs-3110").dest_for
