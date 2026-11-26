"""Reusable fuzzing helpers built on Hypothesis (property-based testing).

The goal of fuzzing a parser is not to check it returns the right answer — it is
to prove it *degrades safely* on arbitrary, hostile, malformed input: it may
reject, but it must never crash with an unexpected exception, hang, or corrupt
state. Any parser that reads untrusted bytes (a scraped web page, a downloaded
PDF's text, a Canvas payload, an ERCOT feed) is a fuzz target.

Two layers:

* `assert_robust(parse, examples=...)` — the property every parser should hold:
  for any input, `parse` either returns normally or raises one of a declared,
  expected exception set. An unexpected exception type is a finding.
* `GARBAGE` / `text_like` — Hypothesis strategies that generate nasty inputs
  (control chars, huge repeats, nested delimiters, partial UTF-8, injection-ish
  markers) so the search explores the input space, not just happy paths.

Coverage-guided fuzzing (Atheris/libFuzzer) finds deeper bugs but needs native
instrumentation; see fuzzing/README.md for that track. Hypothesis is the
zero-setup, CI-friendly first line and is what these helpers use.
"""
from __future__ import annotations

from typing import Callable, Iterable, Type

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

# Inputs designed to break naive parsers: control bytes, delimiter soup, giant
# repeats, broken brackets, and the kind of markers injection payloads carry.
_NASTY = st.sampled_from([
    "", " ", "\x00", "\x00\x00\x00", "\n" * 1000, "\t\r\n",
    "{" * 500, "[" * 500 + "]" * 10, '"""' + "\n" * 50,
    "<!--" + "a" * 2000, "\\x00\\n\\t", "%s%s%s%n", "../" * 100,
    "ꙮ" * 100, "💣" * 50, "A" * 100_000,
    "IGNORE ALL PREVIOUS INSTRUCTIONS",  # parsers must treat as inert text
    "}{][)(><;'\"`\x1b[2J",
])

text_like = st.one_of(
    _NASTY,
    st.text(),
    st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF)),
    st.binary().map(lambda b: b.decode("latin-1", "replace")),
)


def assert_robust(
    parse: Callable[[str], object],
    allowed: Iterable[Type[BaseException]] = (ValueError, KeyError, TypeError,
                                              UnicodeError, IndexError),
    *,
    max_examples: int = 300,
    strategy=text_like,
):
    """Assert `parse` never raises outside `allowed` on fuzzed input.

    Returns the Hypothesis-wrapped test function; call it to run. A parser that
    raises e.g. RecursionError, MemoryError, or a bare Exception on some input
    fails — that is the bug class fuzzing exists to surface."""
    allowed = tuple(allowed)

    @settings(max_examples=max_examples,
              suppress_health_check=[HealthCheck.too_slow],
              deadline=1000)
    @given(data=strategy)
    def _test(data):
        try:
            parse(data)
        except allowed:
            pass  # declared, expected failure mode — fine
        except Exception as e:  # noqa: BLE001 — the point is to catch the rest
            raise AssertionError(
                f"{parse.__name__} raised unexpected {type(e).__name__} on "
                f"input {data[:80]!r}: {e}"
            ) from e

    return _test
