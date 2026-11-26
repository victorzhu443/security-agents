import json
from pathlib import Path

from secprim import write_private


class SessionStore:
    def __init__(self, path):
        self.path = Path(path)

    def save(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        write_private(self.path, json.dumps(data))


def write_session(path, data):
    SessionStore(path).save(data)
