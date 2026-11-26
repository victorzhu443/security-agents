"""RC-2 — bound the cost (size / time / expansion) of processing untrusted input.

Three ceilings cover the symptoms found: a streaming read cap (giant bodies), a
DTD-free XML parse (billion-laughs), and a zip-member budget (zip-bombs and
zip-slip). Plus `redos_probe`, a test helper that times a regex against
adversarial runs, because stdlib `re` has no timeout — the fix for ReDoS is
structural and must be *tested*, not hoped for.
"""
from __future__ import annotations

import re
import time
import zipfile
from typing import Any, Iterable, Iterator, List, Optional, Tuple

from .boundary import MalformedInput

try:  # defusedxml is the stronger backend when present; stdlib is the fallback
    import defusedxml.ElementTree as _ET  # type: ignore
except Exception:  # pragma: no cover
    import xml.etree.ElementTree as _ET  # type: ignore


class TooLarge(MalformedInput):
    """Input exceeded a size/expansion ceiling."""


def _chunks(src: Any, chunk: int) -> Iterator[bytes]:
    """Yield byte chunks from a response, a file-like, or an iterable."""
    if hasattr(src, "iter_bytes"):          # httpx.Response (streamed or not)
        yield from src.iter_bytes()
    elif hasattr(src, "iter_content"):      # requests.Response
        yield from src.iter_content(chunk_size=chunk)
    elif hasattr(src, "read"):              # file-like / urllib response
        while True:
            b = src.read(chunk)
            if not b:
                return
            yield b
    else:                                   # any iterable of bytes
        yield from src


def bounded_read(src: Any, max_bytes: int, *, chunk: int = 65536) -> bytes:
    """Read at most `max_bytes` from `src`; raise TooLarge rather than buffer more.

    Never trusts a Content-Length header — it counts what actually arrives.
    """
    out = bytearray()
    for piece in _chunks(src, chunk):
        out += piece
        if len(out) > max_bytes:
            raise TooLarge(f"body exceeds {max_bytes} bytes")
    return bytes(out)


_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def safe_xml_fromstring(data: Any, *, max_bytes: int = 5_000_000):
    """Parse XML with entity expansion impossible.

    Refuses any document carrying a DOCTYPE/ENTITY declaration (the only way to
    define expanding entities), then parses. Real feeds, OOXML parts and sitemaps
    never need a DTD, so this is lossless for legitimate input.
    """
    raw = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else bytes(data)
    if len(raw) > max_bytes:
        raise TooLarge(f"xml exceeds {max_bytes} bytes")
    if _DTD.search(raw):
        raise MalformedInput("xml: DTD / entity declarations are not allowed")
    try:
        return _ET.fromstring(raw)
    except Exception as e:  # noqa: BLE001 — surface as the boundary type
        raise MalformedInput(f"xml: {e}") from e


def safe_zip_members(zf: zipfile.ZipFile, *, max_member_bytes: int,
                     max_total_bytes: int, max_ratio: float = 100.0
                     ) -> Iterator[zipfile.ZipInfo]:
    """Yield members that fit the budget; refuse bombs and slips *before* reading.

    Checks the member's declared uncompressed size, the running total, the
    compression ratio (a bomb is thousands-to-one), and the name (no absolute
    paths or `..` — zip-slip). Callers then `zf.read(info)` only what passed.
    """
    total = 0
    for info in zf.infolist():
        name = info.filename
        if name.startswith(("/", "\\")) or ".." in name.replace("\\", "/").split("/") \
                or (len(name) > 1 and name[1] == ":"):
            raise MalformedInput(f"zip: unsafe member name {name!r}")
        if info.file_size > max_member_bytes:
            raise TooLarge(f"zip: member {name!r} declares {info.file_size} bytes")
        total += info.file_size
        if total > max_total_bytes:
            raise TooLarge(f"zip: archive expands past {max_total_bytes} bytes")
        if info.compress_size > 0 and info.file_size / info.compress_size > max_ratio:
            raise MalformedInput(f"zip: member {name!r} has a suspicious compression ratio")
        yield info


_DEFAULT_PROBES: Tuple[Tuple[str, str], ...] = (
    ("newlines", "\n"), ("spaces", " "), ("tabs", "\t"), ("mixed-ws", " \t\n"),
    ("open-parens", "("), ("letters", "a"), ("dashes", "-"), ("colons", ":"),
)


def redos_probe(pattern: "re.Pattern[str] | str", *, n: int = 10_000,
                deadline_s: float = 0.1,
                probes: Optional[Iterable[Tuple[str, str]]] = None
                ) -> List[Tuple[str, float]]:
    """Time `pattern` against adversarial runs; raise if any exceeds the deadline.

    A healthy pattern finishes a 10k-char run in well under 100 ms. Catastrophic
    backtracking shows up as seconds. Use in a repo's security suite over every
    regex that sees untrusted text.

    Two things make it safe to point at an unknown pattern:
    - sizes escalate geometrically (8, 12, 18, ... n) and the probe stops at the
      first size over the deadline or growing faster than ~x8 per x1.5 step, so an
      exponential pattern is caught at ~20 chars instead of hanging the suite;
    - every unit is also probed as "run + one foreign character" (the `+tail`
      rows), the shape that makes `^(\w+\s?)*$`-style patterns blow up only when
      the match fails at the very end.
    Returns one (probe, seconds) row per unit and variant at the largest size run.
    """
    rx = re.compile(pattern) if isinstance(pattern, str) else pattern
    sizes: List[int] = []
    size = 8
    while size < n:
        sizes.append(size)
        size = int(size * 1.5) + 1
    sizes.append(n)
    results: List[Tuple[str, float]] = []
    for name, unit in (probes or _DEFAULT_PROBES):
        for variant, tail in (("", ""), ("+tail", "!")):
            prev = 0.0
            dt = 0.0
            for sz in sizes:
                text = (unit * (sz // max(1, len(unit)) + 1))[:sz] + tail
                t0 = time.perf_counter()
                rx.sub("", text)
                rx.search(text)
                dt = time.perf_counter() - t0
                if dt > deadline_s:
                    raise AssertionError(
                        f"ReDoS: {rx.pattern!r} took {dt:.3f}s on {sz} x {name}{variant} "
                        f"(limit {deadline_s}s)")
                if prev > 1e-3 and dt > 8 * prev:
                    raise AssertionError(
                        f"ReDoS: {rx.pattern!r} grew {dt/prev:.0f}x from {prev:.4f}s to {dt:.4f}s "
                        f"between sizes on {name}{variant} (super-polynomial)")
                prev = dt
            results.append((name + variant, dt))
    return results
