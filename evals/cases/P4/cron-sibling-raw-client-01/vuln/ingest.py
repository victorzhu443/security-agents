"""Two ingestion paths. The hourly one was fixed; the nightly archive one was not."""
import httpx
from secprim.safe_fetch import safe_fetch

ALLOW_HOSTS = ["origin.test"]
MAX_BYTES = 1000


def fetch_recent(url, *, resolver, transport):
    return safe_fetch(url, allow_hosts=ALLOW_HOSTS, max_bytes=MAX_BYTES,
                      resolver=resolver, transport=transport).content


def fetch_archive(url, *, resolver, transport):
    # the cron sibling: still the client it always had, redirects followed by name
    with httpx.Client(transport=transport, follow_redirects=True, timeout=120) as c:
        return c.get(url).content


def fetch_page(url, *, resolver, transport):
    """Nightly entry point -> the archive downloader."""
    return fetch_archive(url, resolver=resolver, transport=transport)
