import hashlib


def cache_key(url: str) -> str:
    """Filename for the on-disk fetch cache; a collision only costs a re-fetch."""
    return hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()
