"""redos_probe must catch exponential and tail-triggered patterns quickly, and pass
healthy ones, at the default size."""
import re
import time

import pytest

from secprim.bounded import redos_probe


def test_healthy_pattern_passes_and_reports_both_variants():
    rows = redos_probe(re.compile(r"^[ \t]*(?:-[ \t]*)?(?:set-)?cookie:\s*.*$", re.I | re.M))
    names = {r[0] for r in rows}
    assert "spaces" in names and "spaces+tail" in names
    assert max(r[1] for r in rows) < 0.1


def test_nested_quantifier_is_caught_at_default_n_without_hanging():
    t0 = time.perf_counter()
    with pytest.raises(AssertionError, match="ReDoS"):
        redos_probe(r"^(a+)+$")              # exponential on a-run + tail
    assert time.perf_counter() - t0 < 5.0


def test_tail_triggered_blowup_is_caught():
    # fast on a pure run, catastrophic once the match fails at the end
    with pytest.raises(AssertionError, match=r"\+tail"):
        redos_probe(r"^(\w+\s?)*$", n=10_000)
