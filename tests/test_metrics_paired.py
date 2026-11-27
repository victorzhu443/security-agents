"""The paired-comparison additions to evals/metrics.py and the stats kit in evals/calib/stats.py:
hand-checked values (always on) and scipy / statsmodels oracles (skipped when the `dev` extra
is absent). No model, no docker, no harbor."""
from __future__ import annotations

import math

import pytest

from evals.calib import stats
from evals.metrics import fpr, mcnemar, paired_bootstrap, wilson_ci


# ----------------------------------------------------------------- hand-checked values

def test_mcnemar_hand_checked():
    assert mcnemar(3, 1) == {"b": 3, "c": 1, "n_discordant": 4, "p": 0.625}
    r = mcnemar(10, 0)
    assert r["n_discordant"] == 10 and math.isclose(r["p"], 2 / 1024) and math.isclose(r["p"], 0.001953125)


def test_mcnemar_edges():
    assert mcnemar(0, 0)["p"] == 1.0
    assert mcnemar(4, 4)["p"] == 1.0            # symmetric: capped at 1
    assert mcnemar(1, 0)["p"] == 1.0            # 2 * 0.5
    with pytest.raises(ValueError):
        mcnemar(-1, 2)


def test_paired_bootstrap_identical_arrays():
    r = paired_bootstrap([1, 0, 1, 1, 0], [1, 0, 1, 1, 0])
    assert r == {"delta": 0.0, "ci95": [0.0, 0.0], "n": 5, "p_delta_le_0": 1.0}


def test_paired_bootstrap_reproducible_and_directional():
    a = [0, 0, 1, 1, 0, 1, 0, 0, 1, 0]
    b = [1, 1, 1, 1, 0, 1, 1, 0, 1, 1]
    r1 = paired_bootstrap(a, b, n=2000, seed=7)
    r2 = paired_bootstrap(a, b, n=2000, seed=7)
    assert r1 == r2
    assert math.isclose(r1["delta"], 0.4) and r1["n"] == 10
    assert r1["ci95"][0] <= 0.4 <= r1["ci95"][1] and r1["ci95"][0] > 0.0
    assert r1["p_delta_le_0"] < 0.05
    rev = paired_bootstrap(b, a, n=2000, seed=7)
    assert math.isclose(rev["delta"], -0.4) and rev["p_delta_le_0"] == 1.0


def test_paired_bootstrap_rejects_bad_input():
    with pytest.raises(ValueError):
        paired_bootstrap([1, 0], [1])
    with pytest.raises(ValueError):
        paired_bootstrap([], [])


def test_fpr_is_rate_plus_wilson():
    rate, ci = fpr(1, 8)
    assert rate == 0.125 and ci == wilson_ci(1, 8)
    assert fpr(0, 0) == (0.0, (0.0, 1.0))
    with pytest.raises(ValueError):
        fpr(9, 8)


# ----------------------------------------------------------------- stats kit

def test_power_note_sentence_and_sample_size():
    note = stats.power_note(35, 0.5, 0.15)
    assert note.startswith("With 35 tasks") and "% power" in note and "80%" in note
    need = stats.n_for_power(0.5, 0.15)
    assert 80 <= need <= 100                    # the plan's "80-100 for a 15-point difference"
    assert stats.power(need, 0.5, 0.15) >= 0.79
    assert stats.power(10, 0.5, 0.15) < stats.power(100, 0.5, 0.15)
    assert math.isclose(stats.norm_ppf(0.975), 1.959964, abs_tol=1e-5)


def test_clustered_stderr_hand_value():
    # task means 1.0, 0.0, 0.5, 0.5 -> mean 0.5, sample var = (0.25+0.25+0+0)/3 = 1/6, SE = sqrt(1/6/4)
    per = {"a": [1, 1], "b": [0, 0], "c": [1, 0], "d": [0, 1]}
    assert math.isclose(stats.clustered_stderr(per), math.sqrt((1 / 6) / 4))
    assert stats.clustered_stderr({"a": [1, 1]}) == 0.0
    assert stats.clustered_stderr({"a": [1], "b": [1]}) == 0.0


def test_per_task_pass_and_compare():
    recs = [{"task_id": "t1", "rewards": {"reward": 1.0}}, {"task_id": "t1", "rewards": {"reward": 0.0}},
            {"task_id": "t2", "rewards": {"reward": 1.0}}, {"task_id": "t3", "rewards": None}]
    assert stats.per_task_pass(recs) == {"t1": 0.5, "t2": 1.0, "t3": 0.0}
    assert stats.per_task_pass([{"task_id": "x", "passed": True}], key="passed") == {"x": 1.0}
    a = {"t1": 1.0, "t2": 0.0, "t3": 0.0, "t4": 1.0, "only_a": 1.0}
    b = {"t1": 1.0, "t2": 1.0, "t3": 1.0, "t4": 0.0, "only_b": 0.0}
    r = stats.compare(a, b, n_boot=500)
    assert r["n"] == 4 and r["tasks"] == ["t1", "t2", "t3", "t4"]
    assert r["only_a"] == ["only_a"] and r["only_b"] == ["only_b"]
    assert r["mcnemar"] == mcnemar(1, 2) and math.isclose(r["bootstrap"]["delta"], 0.25)
    assert stats.compare({}, {"x": 1.0})["n"] == 0


# ----------------------------------------------------------------- oracles (dev extra; skipped when absent)

TABLES = [(0, 10), (1, 8), (3, 7), (10, 10), (27, 40), (54, 54), (1, 1), (0, 1)]


def test_wilson_ci_matches_statsmodels():
    sm = pytest.importorskip("statsmodels.stats.proportion")
    z = stats.norm_ppf(0.975)                      # statsmodels uses the exact 1.959964, our default is 1.96
    for k, n in TABLES:
        lo, hi = sm.proportion_confint(k, n, alpha=0.05, method="wilson")
        exact = wilson_ci(k, n, z=z)
        assert math.isclose(exact[0], float(lo), abs_tol=1e-9), (k, n)
        assert math.isclose(exact[1], float(hi), abs_tol=1e-9), (k, n)
        default = wilson_ci(k, n)
        assert abs(default[0] - float(lo)) < 1e-4 and abs(default[1] - float(hi)) < 1e-4, (k, n)


def test_mcnemar_matches_statsmodels_exact():
    ct = pytest.importorskip("statsmodels.stats.contingency_tables")
    for b, c in [(3, 1), (10, 0), (5, 5), (7, 2), (1, 0), (12, 3), (0, 6)]:
        table = [[20, b], [c, 15]]                 # concordant cells do not matter
        want = float(ct.mcnemar(table, exact=True).pvalue)
        assert math.isclose(mcnemar(b, c)["p"], want, abs_tol=1e-12), (b, c)


def test_mcnemar_matches_scipy_binomtest():
    scipy_stats = pytest.importorskip("scipy.stats")
    for b, c in [(3, 1), (10, 0), (7, 2), (12, 3), (0, 6), (4, 4)]:
        want = float(scipy_stats.binomtest(min(b, c), b + c, 0.5, alternative="two-sided").pvalue)
        assert math.isclose(mcnemar(b, c)["p"], want, abs_tol=1e-12), (b, c)


def test_normal_cdf_matches_scipy():
    scipy_stats = pytest.importorskip("scipy.stats")
    for x in (-2.5, -1.0, 0.0, 0.7, 1.96, 3.1):
        assert math.isclose(stats.norm_cdf(x), float(scipy_stats.norm.cdf(x)), abs_tol=1e-12)
    for q in (0.025, 0.2, 0.5, 0.8, 0.975):
        assert math.isclose(stats.norm_ppf(q), float(scipy_stats.norm.ppf(q)), abs_tol=1e-9)
