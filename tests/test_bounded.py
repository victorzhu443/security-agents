"""RC-2 primitives: ceilings hold on oversize/expanding input; benign input passes."""
import io
import re
import zipfile

import pytest

from secprim.boundary import MalformedInput
from secprim.bounded import (TooLarge, bounded_read, safe_xml_fromstring,
                             safe_zip_members, redos_probe)


class _IterBytes:
    def __init__(self, chunks):
        self._c = chunks

    def iter_bytes(self):
        yield from self._c


def test_bounded_read_sources_and_cap():
    assert bounded_read(io.BytesIO(b"abc"), 10) == b"abc"
    assert bounded_read([b"ab", b"cd"], 10) == b"abcd"
    assert bounded_read(_IterBytes([b"x" * 5, b"y" * 5]), 10) == b"x" * 5 + b"y" * 5
    with pytest.raises(TooLarge):
        bounded_read([b"x" * 6, b"y" * 6], 10)
    with pytest.raises(TooLarge):
        bounded_read(io.BytesIO(b"z" * 101), 100)


def test_safe_xml_parses_plain_and_refuses_dtd():
    root = safe_xml_fromstring(b"<sst><si><t>hello</t></si></sst>")
    assert root.tag == "sst"
    with pytest.raises(MalformedInput):
        safe_xml_fromstring(b'<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')
    with pytest.raises(MalformedInput):
        safe_xml_fromstring(b"<!doctype x><x/>")  # case-insensitive
    with pytest.raises(TooLarge):
        safe_xml_fromstring(b"<x>" + b"a" * 50 + b"</x>", max_bytes=10)
    with pytest.raises(MalformedInput):
        safe_xml_fromstring(b"<unclosed>")


def _zip(members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_safe_zip_members_passes_normal_archive():
    zf = _zip([("data/prices.csv", b"a,b\n1,2\n"), ("readme.txt", b"hi")])
    names = [i.filename for i in safe_zip_members(zf, max_member_bytes=1000, max_total_bytes=5000)]
    assert names == ["data/prices.csv", "readme.txt"]


def test_safe_zip_members_refuses_unsafe_names_and_budgets():
    with pytest.raises(MalformedInput):
        list(safe_zip_members(_zip([("../evil.txt", b"x")]), max_member_bytes=10, max_total_bytes=10))
    with pytest.raises(MalformedInput):
        list(safe_zip_members(_zip([("/abs.txt", b"x")]), max_member_bytes=10, max_total_bytes=10))
    with pytest.raises(TooLarge):  # one member over the per-member cap
        list(safe_zip_members(_zip([("big.bin", b"q" * 100)]), max_member_bytes=50,
                              max_total_bytes=1000, max_ratio=10_000))
    with pytest.raises(TooLarge):  # total over the archive cap
        list(safe_zip_members(_zip([("a", b"q" * 60), ("b", b"q" * 60)]), max_member_bytes=100,
                              max_total_bytes=100, max_ratio=10_000))
    with pytest.raises(MalformedInput):  # highly compressible member exceeds the ratio ceiling
        list(safe_zip_members(_zip([("zeros", b"\x00" * 200_000)]), max_member_bytes=10**7,
                              max_total_bytes=10**7, max_ratio=100))


def test_redos_probe_passes_unambiguous_pattern():
    # The study-hub header pattern after the root-cause fix: one whitespace run,
    # a second only reachable after a dash. Fast on every probe class.
    fixed = re.compile(r"(?im)^([ \t]*(?:-[ \t]*)?(?:set-)?cookie:\s*).*$")
    results = redos_probe(fixed, n=10_000, deadline_s=0.1)
    assert all(dt < 0.1 for _, dt in results), results


def test_redos_probe_flags_both_historical_patterns():
    # Pre-fix: `\s` spans newlines under (?m) -> catastrophic on a newline run.
    original = re.compile(r"(?im)^(\s*-?\s*(?:set-)?cookie:\s*).*$")
    with pytest.raises(AssertionError):
        redos_probe(original, n=400, deadline_s=0.05, probes=[("newlines", "\n")])
    # First "fix": narrowed to [ \t] but kept two adjacent quantifiers around an
    # optional dash -> still ~O(n^2) on a run of plain spaces. The default
    # multi-probe set is what catches this; a newline-only check would not.
    first_fix = re.compile(r"(?im)^([ \t]*-?[ \t]*(?:set-)?cookie:\s*).*$")
    with pytest.raises(AssertionError):
        redos_probe(first_fix, n=2_000, deadline_s=0.05, probes=[("spaces", " ")])
    # Small n keeps both checks fast; the probe still flags each.
