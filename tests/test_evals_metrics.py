"""evals.metrics against hand-computed values (z = 1.96 throughout)."""
import math

import pytest

from evals.metrics import fmt_ci, pass_at_k, pass_pow_k, wilson_ci


def _close(a, b, tol=5e-4):
    return all(math.isclose(x, y, abs_tol=tol) for x, y in zip(a, b))


def test_wilson_ci_hand_values():
    # p = 0.5, n = 10: centre stays at 0.5, half-width 0.2634
    assert _close(wilson_ci(5, 10), (0.2366, 0.7634))
    # all failures / all successes never collapse to a point
    assert _close(wilson_ci(0, 10), (0.0, 0.2775))
    assert _close(wilson_ci(10, 10), (0.7225, 1.0))
    # one trial, one success
    assert _close(wilson_ci(1, 1), (0.2065, 1.0))
    # three of three (the --trials 3 smoke run)
    assert _close(wilson_ci(3, 3), (0.4385, 1.0))


def test_wilson_ci_shrinks_with_n_and_is_bounded():
    lo1, hi1 = wilson_ci(50, 100)
    lo2, hi2 = wilson_ci(500, 1000)
    assert hi1 - lo1 > hi2 - lo2
    for k, n in ((0, 1), (1, 1), (0, 1000), (1000, 1000)):
        lo, hi = wilson_ci(k, n)
        assert 0.0 <= lo <= hi <= 1.0


def test_wilson_ci_edge_cases():
    assert wilson_ci(0, 0) == (0.0, 1.0)
    with pytest.raises(ValueError):
        wilson_ci(3, 2)


def test_pass_at_k_unbiased_estimator_hand_values():
    # n = 5 samples, c = 2 passes: 1 - C(5-c, k) / C(5, k)
    assert math.isclose(pass_at_k(5, 2, 1), 0.4)   # 1 - 3/5
    assert math.isclose(pass_at_k(5, 2, 2), 0.7)   # 1 - 3/10
    assert math.isclose(pass_at_k(5, 2, 3), 0.9)   # 1 - 1/10
    assert pass_at_k(5, 2, 4) == 1.0               # fewer than k failures: every draw passes
    assert pass_at_k(5, 2, 5) == 1.0
    assert pass_at_k(3, 0, 1) == 0.0 and pass_at_k(3, 3, 3) == 1.0
    # pass@1 is just c/n
    assert math.isclose(pass_at_k(10, 7, 1), 0.7)


def test_pass_at_k_rejects_bad_inputs():
    with pytest.raises(ValueError):
        pass_at_k(3, 4, 1)
    with pytest.raises(ValueError):
        pass_at_k(3, 1, 4)
    with pytest.raises(ValueError):
        pass_at_k(3, 1, 0)


def test_pass_pow_k_is_consistency_not_coverage():
    assert pass_pow_k(1.0, 10) == 1.0
    assert math.isclose(pass_pow_k(0.9, 2), 0.81)
    assert math.isclose(pass_pow_k(0.5, 3), 0.125)
    # pass^k only falls as k grows; pass@k only rises
    assert pass_pow_k(0.7, 3) < pass_pow_k(0.7, 2) < pass_pow_k(0.7, 1)
    assert pass_at_k(10, 7, 1) < pass_at_k(10, 7, 2) < pass_at_k(10, 7, 3)
    with pytest.raises(ValueError):
        pass_pow_k(1.2, 1)


def test_fmt_ci_shape():
    assert fmt_ci(0.9615, (0.8700, 0.9949)) == "0.96 [0.87, 0.99]"
