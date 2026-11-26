import ipaddress
import httpx


def _is_public(host, resolver):
    return all(ipaddress.ip_address(info[4][0]).is_global for info in resolver(host, None))


def fetch_page(url, *, resolver, transport):
    host = httpx.URL(url).host
    if not _is_public(host, resolver):
        raise ValueError(f"{host} is not public")
    with httpx.Client(transport=transport) as c:   # connects by name: resolves again
        return c.get(url).content
