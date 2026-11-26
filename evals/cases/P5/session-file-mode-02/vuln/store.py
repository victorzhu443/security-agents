import json
from pathlib import Path


class SessionStore:
    def __init__(self, path):
        self.path = Path(path)

    def save(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data))      # umask default, group/other readable


def write_session(path, data):
    SessionStore(path).save(data)
