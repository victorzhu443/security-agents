import re
HEADER = re.compile(r"(?im)^([ \t]*-?[ \t]*(?:set-)?cookie:\s*).*$")   # first fix: still ambiguous
