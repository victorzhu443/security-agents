"""fuzzing: the RC-2 `size_sweep` cost property and the Atheris harness's pure parts.

`assert_robust` is covered in tests/test_toolkit.py. Atheris itself is not
importable on macOS (no libFuzzer in Apple Clang), so the harness tests cover
only what runs without it: the per-input callback, exception resolution, and
the error you get when `atheris` is missing."""
import re

import pytest

from fuzzing.fuzz_lib import size_sweep, SweepRow
from fuzzing import atheris_harness as ah


# --- size_sweep -------------------------------------------------------------

def linear_parse(s: str) -> int:
    """O(n): a split, a count, and a linear regex — the shape of a healthy parser."""
    return len(s.split("\n")) + s.count("(") + len(re.findall(r"[a-z]+", s))


def quadratic_parse(s: str) -> int:
    """O(n^2): re-copies every prefix, as a 'rebuild the buffer per token' loop
    does. ~3 ms at 10k chars, ~250 ms at 100k on an M-series laptop: ~80x for
    10x the input, against the 25x limit."""
    return sum(len("".join([s[:i], "x"])) for i in range(len(s)))


def test_linear_parser_passes_and_returns_the_table():
    rows = size_sweep(linear_parse)
    assert all(isinstance(r, SweepRow) for r in rows)
    # every (unit, size) pair measured, in order
    assert [(r.unit, r.size) for r in rows] == [
        (u, n) for u in (" ", "\n", "a", "(", "<", "{") for n in (1_000, 10_000, 100_000)
    ]
    assert all(r.seconds >= 0 for r in rows)


def test_quadratic_parser_is_flagged_as_super_linear():
    # Deadline deliberately lax so the *growth* check is what fires; the noise
    # floor is lowered so a much faster machine cannot skip the ratio step.
    with pytest.raises(AssertionError, match=r"super-linear on 'a'"):
        size_sweep(quadratic_parse, sizes=(10_000, 100_000), units=("a",),
                   deadline_s=30, noise_floor_s=0.0001, repeat=1)


def test_deadline_is_enforced():
    def slow(s):
        if len(s) >= 10_000:
            import time
            time.sleep(0.05)
    with pytest.raises(AssertionError, match=r"deadline 0.01s"):
        size_sweep(slow, sizes=(1_000, 10_000), units=("a",), deadline_s=0.01, repeat=1)


def test_declared_rejections_count_as_cheap():
    def rejects(s):
        raise ValueError("no")
    rows = size_sweep(rejects, units=(" ",))
    assert len(rows) == 3


def test_undeclared_exception_propagates():
    def boom(s):
        raise RecursionError("deep")
    with pytest.raises(RecursionError):
        size_sweep(boom, units=(" ",))


def test_sweep_rejects_bad_arguments():
    with pytest.raises(ValueError):
        size_sweep(linear_parse, sizes=(1_000,))
    with pytest.raises(ValueError):
        size_sweep(linear_parse, units=("",))


# --- atheris_harness (no atheris needed) ------------------------------------

def test_make_one_decodes_swallows_declared_and_propagates_the_rest():
    seen = []

    def target(s):
        seen.append(s)
        if s == "bad":
            raise ValueError("declared")
        if s == "worse":
            raise RecursionError("undeclared")

    one = ah.make_one(target, (ValueError,))
    one(b"\xff\xfeok")               # invalid UTF-8 is replaced, not raised
    assert seen[-1] == "��ok"
    one(b"bad")                       # declared: swallowed
    with pytest.raises(RecursionError):
        one(b"worse")                 # undeclared: libFuzzer would record this


def test_resolve_allowed_accepts_builtins_and_dotted_paths():
    got = ah.resolve_allowed(["ValueError", " KeyError ", "secprim.boundary.MalformedInput", ""])
    from secprim.boundary import MalformedInput
    assert got == (ValueError, KeyError, MalformedInput)
    with pytest.raises(ValueError):
        ah.resolve_allowed(["len"])
    with pytest.raises(ValueError):
        ah.resolve_allowed(["NotAnExceptionAnywhere"])


def test_default_seed_dir_follows_the_convention():
    def redact(s):
        return s
    d = ah.default_seed_dir(redact)
    assert d is not None and d.name == "redact" and d.parent.name == "seeds"

    def nothing_here(s):
        return s
    assert ah.default_seed_dir(nothing_here) is None


def test_missing_atheris_is_a_clear_error():
    try:
        import atheris  # noqa: F401
    except ImportError:
        pass
    else:
        pytest.skip("atheris is installed here; the native path is exercised by run_atheris.sh")
    with pytest.raises(SystemExit, match="run_atheris.sh"):
        ah.fuzz(lambda s: s, runs=1)
