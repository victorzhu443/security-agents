import re

_TAG = re.compile(r"<[^<>]+>")
_SPACE = re.compile(r"[ \t]+")


def html_to_text(html: str) -> str:
    return _SPACE.sub(" ", _TAG.sub(" ", html))


def fetch_html_as_text(response) -> str:
    """HTML-only papers: strip the fetched page to text."""
    return html_to_text(response.text)              # the whole body, however large
