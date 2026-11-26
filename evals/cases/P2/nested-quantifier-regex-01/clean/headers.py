import re
KEY_LIST = re.compile(r"^\w+(?:\s+\w+)*\s*:")   # separator mandatory: one way to split a run
