"""P4 egress grader (plugin): where did the fetcher actually connect?

    egress   expect: {target: "mod:fn", allowed_hosts: [...], max_bytes: N,
                      scenarios: [redirect_private, redirect_loopback, rebinding,
                                  off_list, derived_links, oversize]}

The target is `fn(url, *, resolver, transport)`. The grader injects a
getaddrinfo-compatible resolver backed by a table (public, private, loopback and
a flapping answer) and an `httpx.MockTransport` that records every request and
serves scripted responses (redirects, link pages, oversize bodies). Nothing
touches the network.

Detected = in any scenario the recorded connection sequence reaches a non-public
address, a host outside `allowed_hosts`, or the function hands back more than
`max_bytes`. A hostname in a recorded request is resolved *again* at
"connect time" through the same resolver, which is what a real client would do:
a fetcher that validates the name and then connects by name is caught by the
flapping answer (DNS rebinding); one that connects to the address it validated
(`secprim.safe_fetch`) sends IP literals and is not.

Any library can be the vuln as long as it honours the injected transport (httpx
does); a `requests`-based fetcher cannot be driven offline and is out of scope.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Tuple

from secprim.safe_fetch import _host_allowed, _is_safe

from .graders import Case, Result, load_attr

PUBLIC = "93.184.216.34"
PUBLIC_2 = "93.184.216.35"
PRIVATE = "10.1.2.3"

TABLE: Dict[str, Any] = {
    "origin.test": PUBLIC,
    "cdn.origin.test": PUBLIC,
    "evil.test": PUBLIC_2,                 # public, but not on any case's allow-list
    "internal.test": PRIVATE,
    "flap.test": [PUBLIC, "127.0.0.1"],    # first answer public, every later one loopback
}

LINK_PAGE = (b"<html><body>"
             b'<a href="http://origin.test/files/a.pdf">a</a>'
             b'<a href="http://evil.test/files/b.pdf">b</a>'
             b'<a href="http://10.0.0.9/files/c.pdf">c</a>'
             b"</body></html>")

ALL_SCENARIOS = ["redirect_private", "redirect_loopback", "rebinding",
                 "off_list", "derived_links", "oversize"]


def make_resolver(table: Dict[str, Any]):
    """getaddrinfo-compatible; list-valued entries answer in order (last repeats)."""
    calls: List[str] = []
    counts: Dict[str, int] = {}

    def _resolve(host, port=None, *a, **k):
        calls.append(host)
        if host not in table:
            raise OSError(f"{host}: name not known")
        answers = table[host]
        if isinstance(answers, list):
            i = counts.get(host, 0)
            counts[host] = i + 1
            answers = [answers[min(i, len(answers) - 1)]]
        else:
            answers = [answers]
        return [(None, None, None, "", (ip, 0)) for ip in answers]

    _resolve.calls = calls
    return _resolve


def make_transport(routes: Dict[str, Tuple[int, Dict[str, str], bytes]]):
    import httpx
    seen: List[Any] = []

    def handler(request):
        seen.append(request)
        status, headers, body = routes.get(request.url.path, (200, {}, b"ok"))
        return httpx.Response(status, headers=headers, content=body)

    t = httpx.MockTransport(handler)
    t.seen = seen
    return t


def scenario(name: str, max_bytes: int):
    """(start_url, routes) for one scenario."""
    if name == "redirect_private":
        return "http://origin.test/start", {"/start": (302, {"location": "http://internal.test/"}, b"")}
    if name == "redirect_loopback":
        return "http://origin.test/start", {"/start": (302, {"location": "http://127.0.0.1:8080/admin"}, b"")}
    if name == "rebinding":
        return "http://flap.test/start", {}
    if name == "off_list":
        return "http://evil.test/start", {}
    if name == "derived_links":
        return "http://origin.test/start", {"/start": (200, {"content-type": "text/html"}, LINK_PAGE)}
    if name == "oversize":
        return "http://origin.test/start", {"/start": (200, {}, b"x" * (max_bytes + 1))}
    raise ValueError(f"unknown egress scenario {name!r}")


def _body_len(rv) -> int:
    if rv is None:
        return 0
    if hasattr(rv, "content"):
        rv = rv.content
    if isinstance(rv, str):
        rv = rv.encode("utf-8", "replace")
    return len(rv) if isinstance(rv, (bytes, bytearray)) else 0


class EgressGrader:
    name = "egress"

    def grade(self, case: Case, variant: str) -> Result:
        try:
            import httpx  # noqa: F401
        except Exception:  # pragma: no cover
            return Result(False, error="httpx not installed")
        try:
            fn = load_attr(case.variant_dir(variant), case.expect["target"])
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        allowed = case.expect.get("allowed_hosts")
        max_bytes = int(case.expect.get("max_bytes", 1000))
        names = case.expect.get("scenarios", ALL_SCENARIOS)

        breaches: List[str] = []
        metrics: Dict[str, Any] = {}
        for name in names:
            start, routes = scenario(name, max_bytes)
            resolver = make_resolver(TABLE)
            transport = make_transport(routes)
            raised = None
            rv = None
            try:
                rv = fn(start, resolver=resolver, transport=transport)
            except Exception as e:  # noqa: BLE001 — refusing is the safe outcome
                raised = type(e).__name__
            found = self._breaches(transport.seen, resolver, allowed)
            if _body_len(rv) > max_bytes:
                found.append(f"returned {_body_len(rv)} bytes > cap {max_bytes}")
            metrics[name] = {"requests": [str(r.url) for r in transport.seen],
                             "raised": raised, "breaches": found}
            breaches += [f"{name}: {b}" for b in found]
        return Result(detected=bool(breaches), metrics=metrics,
                      evidence="; ".join(breaches)[:400] or "no connection left the allowed public set")

    @staticmethod
    def _breaches(seen, resolver, allowed) -> List[str]:
        out: List[str] = []
        for req in seen:
            host = req.url.host
            try:
                ips = [ipaddress.ip_address(host)]
                literal = True
            except ValueError:
                literal = False
                try:  # connect-time resolution: what a by-name client would hit now
                    ips = [ipaddress.ip_address(i[4][0]) for i in resolver(host, None)]
                except OSError:
                    ips = []
            for ip in ips:
                if not _is_safe(ip):
                    out.append(f"connected to non-public {ip} for {host}")
            name = req.headers.get("host", host).split(":")[0].strip("[]") if literal else host
            if allowed is not None and not _host_allowed(name, allowed):
                out.append(f"connected to off-list host {name}")
        return out


GRADERS = {"egress": EgressGrader()}
