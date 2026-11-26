"""RC-4 primitive: the fetch connects to the address it validated, re-validates every
hop, refuses non-public destinations and bad schemes, and caps the body.

Runs fully offline: the resolver is a dict and the transport is httpx.MockTransport.
"""
import pytest

httpx = pytest.importorskip("httpx")

from secprim.bounded import TooLarge  # noqa: E402
from secprim.safe_fetch import (safe_fetch, resolve_and_validate,  # noqa: E402
                                UnsafeDestination, TooManyRedirects)

PUBLIC = "93.184.216.34"


def resolver_from(table):
    """getaddrinfo-compatible resolver backed by a dict; counts calls."""
    calls = []

    def _resolve(host, port, *a, **k):
        calls.append(host)
        ips = table[host]
        ips = ips if isinstance(ips, list) else [ips]
        return [(None, None, None, "", (ip, 0)) for ip in ips]

    _resolve.calls = calls
    return _resolve


def transport_with(routes):
    """MockTransport: routes = {path: (status, headers, body)}; records requests."""
    seen = []

    def handler(request):
        seen.append(request)
        status, headers, body = routes.get(request.url.path, (404, {}, b""))
        return httpx.Response(status, headers=headers, content=body)

    t = httpx.MockTransport(handler)
    t.seen = seen
    return t


def test_connects_to_validated_ip_with_real_host_header():
    res = resolver_from({"example.test": PUBLIC})
    tr = transport_with({"/page": (200, {}, b"<html>ok</html>")})
    r = safe_fetch("http://example.test/page", resolver=res, transport=tr)
    assert r.status_code == 200 and r.text == "<html>ok</html>"
    assert r.pinned_ip == PUBLIC
    req = tr.seen[0]
    assert req.url.host == PUBLIC                      # TCP target is the validated IP
    assert req.headers["host"] == "example.test"       # HTTP Host is the real name
    assert req.extensions.get("sni_hostname") == "example.test"


def test_a_changing_dns_answer_cannot_redirect_the_connection():
    # The resolver answers public first and private afterwards. Because the fetch
    # resolves exactly once per hop and connects to that address, the later
    # answer is never consulted: the connection still goes to the public IP.
    answers = iter([PUBLIC, "127.0.0.1", "127.0.0.1"])
    calls = []

    def flapping(host, port, *a, **k):
        calls.append(host)
        return [(None, None, None, "", (next(answers), 0))]

    tr = transport_with({"/": (200, {}, b"ok")})
    r = safe_fetch("http://flap.test/", resolver=flapping, transport=tr)
    assert calls == ["flap.test"]                      # one lookup for the one hop
    assert tr.seen[0].url.host == PUBLIC and r.pinned_ip == PUBLIC


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.9", "169.254.169.254",
                                "0.0.0.0", "::1", "fd00::1", "::ffff:127.0.0.1",
                                "::ffff:169.254.169.254", "100.64.0.1"])
def test_non_public_destinations_are_refused(ip):
    with pytest.raises(UnsafeDestination):
        resolve_and_validate("h.test", resolver_from({"h.test": ip}))
    with pytest.raises(UnsafeDestination):
        safe_fetch(f"http://{ip if ':' not in ip else '[' + ip + ']'}/",
                   resolver=resolver_from({}), transport=transport_with({}))


def test_mixed_public_and_private_answers_are_refused():
    with pytest.raises(UnsafeDestination):
        resolve_and_validate("h.test", resolver_from({"h.test": [PUBLIC, "10.0.0.1"]}))


def test_redirect_hops_are_revalidated():
    res = resolver_from({"ok.test": PUBLIC, "internal.test": "10.1.2.3"})
    tr = transport_with({"/start": (302, {"location": "http://internal.test/"}, b"")})
    with pytest.raises(UnsafeDestination):
        safe_fetch("http://ok.test/start", resolver=res, transport=tr)
    assert len(tr.seen) == 1  # hop 2 was refused before any connection


def test_redirect_to_disallowed_scheme_is_refused():
    res = resolver_from({"ok.test": PUBLIC})
    tr = transport_with({"/start": (302, {"location": "file:///etc/hostname"}, b"")})
    with pytest.raises(UnsafeDestination):
        safe_fetch("http://ok.test/start", resolver=res, transport=tr)


def test_relative_redirect_is_followed_and_pinned():
    res = resolver_from({"ok.test": PUBLIC})
    tr = transport_with({"/a": (302, {"location": "/b"}, b""), "/b": (200, {}, b"done")})
    r = safe_fetch("http://ok.test/a", resolver=res, transport=tr)
    assert r.text == "done" and r.url == "http://ok.test/b"
    assert all(req.url.host == PUBLIC for req in tr.seen)


def test_allow_list_blocks_off_list_hosts_and_permits_suffixes():
    res = resolver_from({"api.canvas.test": PUBLIC, "evil.test": PUBLIC})
    tr = transport_with({"/": (200, {}, b"ok")})
    assert safe_fetch("http://api.canvas.test/", allow_hosts=["canvas.test"],
                      resolver=res, transport=tr).text == "ok"
    with pytest.raises(UnsafeDestination):
        safe_fetch("http://evil.test/", allow_hosts=["canvas.test"], resolver=res, transport=tr)


def test_body_cap_and_redirect_limit():
    res = resolver_from({"ok.test": PUBLIC})
    with pytest.raises(TooLarge):
        safe_fetch("http://ok.test/", max_bytes=10, resolver=res,
                   transport=transport_with({"/": (200, {}, b"x" * 11)}))
    loop = transport_with({"/": (302, {"location": "/"}, b"")})
    with pytest.raises(TooManyRedirects):
        safe_fetch("http://ok.test/", max_redirects=3, resolver=res, transport=loop)
    assert len(loop.seen) == 4
