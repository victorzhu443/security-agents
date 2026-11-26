import json

from secprim import write_private


def write_session(path, data):
    write_private(path, json.dumps(data))  # 0600, atomic, regardless of umask
