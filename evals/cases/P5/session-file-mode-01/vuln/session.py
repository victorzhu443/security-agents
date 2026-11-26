import json


def write_session(path, data):
    with open(path, "w") as f:            # mode comes from the umask: 0644 on a laptop
        json.dump(data, f)
