import re
import httpx

HREF = re.compile(r'href="([^"]+)"')


def fetch_page(url, *, resolver, transport):
    """Fetch the resources page, then every file it links to."""
    with httpx.Client(transport=transport, follow_redirects=True) as c:
        page = c.get(url).text
        return b"".join(c.get(href).content for href in HREF.findall(page))
