import re
from urllib.parse import urlparse

from secprim.safe_fetch import _host_allowed, safe_fetch

HREF = re.compile(r'href="([^"]+)"')
ALLOW_HOSTS = ["origin.test"]
MAX_BYTES = 1000


def host_allowed(href):
    p = urlparse(href)
    return p.scheme in ("http", "https") and bool(p.hostname) and _host_allowed(p.hostname, ALLOW_HOSTS)


def fetch_page(url, *, resolver, transport):
    """Fetch the resources page, then only the linked files on our own hosts."""
    fetch = lambda u: safe_fetch(u, allow_hosts=ALLOW_HOSTS, max_bytes=MAX_BYTES,  # noqa: E731
                                 resolver=resolver, transport=transport)
    page = fetch(url).text
    links = [h for h in HREF.findall(page) if host_allowed(h)]   # off-list hrefs are skipped, logged upstream
    return b"".join(fetch(h).content for h in links)
