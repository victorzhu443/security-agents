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

* `size_sweep(parse)` — the RC-2 cost property for parsers: time `parse` on
  runs of a few characters at 1k / 10k / 100k and fail if any run passes a
  deadline or the growth is clearly super-linear. `secprim.bounded.redos_probe`
  is the same idea for a single regex; this one is for whole parsers.

Coverage-guided fuzzing (Atheris/libFuzzer) finds deeper bugs but needs native
instrumentation; see fuzzing/atheris_harness.py and fuzzing/README.md for that
track. Hypothesis is the zero-setup, CI-friendly first line and is what these
helpers use.
"""
from __future__ import annotations

import math
import time
from typing import Callable, Iterable, List, NamedTuple, Sequence, Type

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
                f"input {repr(data)[:80]}: {e}"
            ) from e

    return _test


class SweepRow(NamedTuple):
    """One timing from `size_sweep`: `unit` repeated to `size` chars took `seconds`."""
    unit: str
    size: int
    seconds: float


# Runs of a single character are what make quantifier-heavy regexes and
# "scan to the next delimiter" loops go quadratic: whitespace (header indents,
# line splitting), a plain letter (token scanning), and the openers that a
# bracket-matching or markup parser pushes without ever popping.
_SWEEP_UNITS: tuple = (" ", "\n", "a", "(", "<", "{")


def size_sweep(
    parse: Callable[[str], object],
    *,
    sizes: Sequence[int] = (1_000, 10_000, 100_000),
    units: Iterable[str] = _SWEEP_UNITS,
    deadline_s: float = 0.5,
    max_exponent: float = 1.4,
    noise_floor_s: float = 0.001,
    repeat: int = 3,
    allowed: Iterable[Type[BaseException]] = (ValueError, KeyError, TypeError,
                                              UnicodeError, IndexError),
) -> List[SweepRow]:
    """Time `parse` on runs of each unit at each size; fail on cost blow-ups.

    This is the RC-2 cost property for a parser: processing untrusted input must
    stay cheap *and* grow about linearly with its length. Two assertions:

    * every run finishes under `deadline_s` (a hang is the obvious symptom);
    * between consecutive sizes, time grows no faster than size**`max_exponent`.
      With the default 1.4, a 10x larger input may take at most ~25x longer, so
      an O(n^2) parser (100x) is flagged while timer jitter around linear is not.
      Steps whose smaller timing is under `noise_floor_s` are too fast to ratio
      meaningfully and are skipped — a parser that fast is not the problem.

    Each timing is the best of `repeat` runs, which filters GC pauses and
    scheduler noise. Exceptions in `allowed` count as a normal (fast) rejection;
    anything else propagates — that is `assert_robust`'s property, not this one.

    Returns every (unit, size, seconds) row so a test can print the table.
    `secprim.bounded.redos_probe` does the same for one regex; use this over the
    function that *calls* the regexes, so the whole path is measured.
    """
    allowed = tuple(allowed)
    sizes = sorted(set(int(n) for n in sizes))
    if len(sizes) < 2:
        raise ValueError("size_sweep needs at least two sizes to measure growth")
    repeat = max(1, repeat)
    rows: List[SweepRow] = []
    for unit in units:
        if not unit:
            raise ValueError("size_sweep units must be non-empty strings")
        prev: "SweepRow | None" = None
        for n in sizes:
            text = (unit * (n // len(unit) + 1))[:n]
            best = math.inf
            for _ in range(repeat):
                t0 = time.perf_counter()
                try:
                    parse(text)
                except allowed:
                    pass
                best = min(best, time.perf_counter() - t0)
            row = SweepRow(unit, n, best)
            rows.append(row)
            if best > deadline_s:
                raise AssertionError(
                    f"cost: {parse.__name__} took {best:.3f}s on {n} x {unit!r} "
                    f"(deadline {deadline_s}s)")
            if prev is not None and prev.seconds >= noise_floor_s:
                limit = (n / prev.size) ** max_exponent
                ratio = best / prev.seconds
                if ratio > limit:
                    raise AssertionError(
                        f"cost: {parse.__name__} is super-linear on {unit!r}: "
                        f"{prev.size} chars took {prev.seconds:.4f}s, {n} chars took "
                        f"{best:.4f}s ({ratio:.0f}x for {n // prev.size}x the input; "
                        f"limit {limit:.0f}x)")
            prev = row
    return rows
