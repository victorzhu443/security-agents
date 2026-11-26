from secprim.safe_fetch import safe_fetch


def fetch_page(url, *, resolver, transport):
    return safe_fetch(url, max_bytes=1000, resolver=resolver, transport=transport).content
