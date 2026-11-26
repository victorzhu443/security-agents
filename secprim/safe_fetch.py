"""RC-4 — a pinned, egress-validated HTTP fetch.

The SSRF guards found in the projects all shared one gap: they validated the
host, then let the HTTP client resolve it *again* to connect. A DNS answer that
changes between those two lookups (rebinding) reaches an internal address with
the check already passed. This primitive closes that by connecting to the exact
address it validated:

  resolve once -> every address must be global -> connect to THAT ip,
  sending the real Host header and SNI so TLS still verifies the hostname
  -> repeat per redirect hop (never auto-follow) -> read the body under a cap.

An optional `allow_hosts` list is the backstop for fetchers that only ever talk
to known services; with it, redirect-to-internal is impossible by construction.
Requires httpx. The resolver and transport are injectable so the whole thing is
unit-testable offline.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any, Callable, Iterable, List, Mapping, Optional, Sequence, Union
from urllib.parse import urljoin, urlparse

from .boundary import MalformedInput
from .bounded import bounded_read

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None  # type: ignore

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Resolver = Callable[..., Any]  # socket.getaddrinfo-compatible


class UnsafeDestination(MalformedInput):
    """The URL points somewhere the fetcher must not go."""


class TooManyRedirects(MalformedInput):
    pass


@dataclass
class SafeResponse:
    status_code: int
    headers: Mapping[str, str]
    content: bytes
    url: str                    # the final (logical) URL, after redirects
    pinned_ip: str              # the address actually connected to

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")


def _is_safe(ip: IPAddress) -> bool:
    # is_global is False for loopback, private, link-local (169.254.169.254),
    # unspecified, reserved, CGNAT and IPv4-mapped forms of those.
    return bool(ip.is_global) and not ip.is_multicast


def resolve_and_validate(hostname: str, resolver: Resolver = socket.getaddrinfo
                         ) -> List[IPAddress]:
    """All addresses for `hostname`; raise unless every one is public."""
    try:  # an IP literal needs no lookup
        ips: List[IPAddress] = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            infos = resolver(hostname, None)
        except (socket.gaierror, OSError) as e:
            raise UnsafeDestination(f"could not resolve {hostname}: {e}") from e
        ips = []
        for info in infos:
            try:
                ips.append(ipaddress.ip_address(info[4][0]))
            except (ValueError, IndexError, TypeError):
                continue
    if not ips:
        raise UnsafeDestination(f"{hostname} resolved to no addresses")
    for ip in ips:
        if not _is_safe(ip):
            raise UnsafeDestination(f"{hostname} resolves to non-public address {ip}")
    # Prefer IPv4 when both exist; keep order otherwise.
    return sorted(set(ips), key=lambda a: (a.version != 4, str(a)))


def _host_allowed(host: str, allow_hosts: Iterable[str]) -> bool:
    h = host.lower().rstrip(".")
    for a in allow_hosts:
        a = a.lower().lstrip(".").rstrip(".")
        if h == a or h.endswith("." + a):
            return True
    return False


def _pinned(parsed, ip: IPAddress) -> str:
    """The same URL with the host replaced by the validated IP."""
    host = f"[{ip}]" if ip.version == 6 else str(ip)
    netloc = host + (f":{parsed.port}" if parsed.port else "")
    return parsed._replace(netloc=netloc).geturl()


def safe_fetch(url: str, *, allow_hosts: Optional[Sequence[str]] = None,
               max_bytes: int = 5_000_000, max_redirects: int = 5,
               timeout: float = 10.0, resolver: Resolver = socket.getaddrinfo,
               transport: Any = None, headers: Optional[Mapping[str, str]] = None,
               ) -> SafeResponse:
    """GET `url` safely. See module docstring for the guarantees."""
    if httpx is None:  # pragma: no cover
        raise RuntimeError("safe_fetch requires httpx")

    client_kwargs = dict(follow_redirects=False, timeout=timeout)
    if transport is not None:
        client_kwargs["transport"] = transport

    with httpx.Client(**client_kwargs) as client:
        current = url
        for _hop in range(max_redirects + 1):
            p = urlparse(current)
            if p.scheme not in ("http", "https"):
                raise UnsafeDestination(f"scheme {p.scheme!r} is not allowed")
            host = p.hostname
            if not host:
                raise UnsafeDestination("URL has no host")
            if allow_hosts is not None and not _host_allowed(host, allow_hosts):
                raise UnsafeDestination(f"{host} is not in the allow-list")

            ip = resolve_and_validate(host, resolver)[0]
            pinned_url = _pinned(p, ip)

            # Host header carries the real name (+ non-default port); SNI too, so
            # certificate verification checks `host`, not the IP we connected to.
            host_header = host if p.port is None else f"{host}:{p.port}"
            req_headers = {"Host": host_header}
            if headers:
                req_headers.update(headers)

            with client.stream("GET", pinned_url, headers=req_headers,
                               extensions={"sni_hostname": host}) as resp:
                if resp.is_redirect:
                    location = resp.headers.get("location")
                    if not location:
                        raise UnsafeDestination("redirect without a Location")
                    current = urljoin(current, location)
                    continue
                body = bounded_read(resp, max_bytes)
                return SafeResponse(status_code=resp.status_code,
                                    headers=dict(resp.headers), content=body,
                                    url=current, pinned_ip=str(ip))
        raise TooManyRedirects(f"more than {max_redirects} redirects")
