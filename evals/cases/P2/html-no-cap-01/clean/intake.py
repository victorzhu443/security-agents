import re

from secprim import bounded_read

MAX_HTML_BYTES = 2 * 1024 * 1024    # a paper page is far under this
_TAG = re.compile(r"<[^<>]+>")
_SPACE = re.compile(r"[ \t]+")


def html_to_text(html: str) -> str:
    return _SPACE.sub(" ", _TAG.sub(" ", html))


def fetch_html_as_text(response) -> str:
    """HTML-only papers: strip the fetched page to text."""
    # RC-2: count what arrives (never trust Content-Length); TooLarge past the cap
    html = bounded_read(response, MAX_HTML_BYTES).decode("utf-8", "replace")
    return html_to_text(html)
