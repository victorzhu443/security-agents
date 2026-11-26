import httpx
from secprim.safe_fetch import resolve_and_validate


def fetch_page(url, *, resolver, transport):
    host = httpx.URL(url).host
    resolve_and_validate(host, resolver)          # checks hop 0 only
    with httpx.Client(transport=transport, follow_redirects=True) as c:
        return c.get(url).content                 # hop 1+ goes wherever Location says
