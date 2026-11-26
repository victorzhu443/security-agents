import re
HEADER = re.compile(r"(?im)^([ \t]*(?:-[ \t]*)?(?:set-)?cookie:\s*).*$")  # one parse per whitespace run
