import re

# Linear-time stripping (RC-2). `<[^<>]+>` cannot straddle tags, so it is linear;
# script/style blocks are removed by a single forward scan (find opener, find its
# closer, jump past it) because any regex that must pair an opener with a closer
# re-scans to the end from every unterminated opener and goes quadratic.
_TAG = re.compile(r"<[^<>]+>")
_SS_OPEN = re.compile(r"<(script|style)\b", re.I)
_NBSP = re.compile(r"&nbsp;")
_HSPACE = re.compile(r"[ \t]+")
_BLANKS = re.compile(r"\n[ \t\r\f\v]*\n+")


def _strip_script_style(html: str) -> str:
    out = []
    low = html.lower()
    i = 0
    while True:
        m = _SS_OPEN.search(html, i)
        if m is None:
            out.append(html[i:])
            break
        out.append(html[i:m.start()])
        close = low.find(f"</{m.group(1).lower()}>", m.end())
        if close < 0:            # unterminated block: everything after it is script, drop it
            break
        i = close + len(m.group(1)) + 3
    return " ".join(out)


def html_to_text(html: str) -> str:
    """Strip an HTML-only paper page to text."""
    text = _TAG.sub(" ", _strip_script_style(html))
    text = _HSPACE.sub(" ", _NBSP.sub(" ", text))
    return _BLANKS.sub("\n\n", text)
