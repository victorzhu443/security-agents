"""Both ingestion paths share one pinned, capped, allow-listed fetch helper."""
from secprim.safe_fetch import safe_fetch

ALLOW_HOSTS = ["origin.test"]
MAX_BYTES = 1000


def _fetch(url, *, resolver, transport):
    return safe_fetch(url, allow_hosts=ALLOW_HOSTS, max_bytes=MAX_BYTES,
                      resolver=resolver, transport=transport).content


def fetch_recent(url, *, resolver, transport):
    return _fetch(url, resolver=resolver, transport=transport)


def fetch_archive(url, *, resolver, transport):
    return _fetch(url, resolver=resolver, transport=transport)


def fetch_page(url, *, resolver, transport):
    """Nightly entry point -> the archive downloader."""
    return fetch_archive(url, resolver=resolver, transport=transport)
