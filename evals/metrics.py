"""The metrics vocabulary the labs' eval reports share (EVALS-PLAN.md Layer 6).

    wilson_ci(k, n)        95% interval for a proportion k/n (Wilson score; no 0-width
                           intervals at 0/n or n/n, unlike the normal approximation)
    pass_at_k(n, c, k)     P(at least one of k samples passes), estimated without bias
                           from n samples of which c passed (Chen et al. 2021, Codex)
    pass_pow_k(p, k)       P(all k samples pass) = p**k — τ-bench's pass^k, the
                           consistency metric: how reliably, not how often

Paired comparisons (evals/calib, Phase 1: two runs on the SAME tasks; the task is the
unit, k trials of one task are correlated and collapse to one per-task value first):

    paired_bootstrap(a, b)  bootstrap of mean(b) - mean(a) over task-level paired samples,
                            95% percentile interval, P(delta <= 0); seeded, reproducible
    mcnemar(b, c)           exact two-sided binomial test on the discordant pairs
                            (b = A passes & B fails, c = A fails & B passes); no scipy
    fpr(fp, negatives)      false-positive rate over negative controls with its Wilson CI

All pure functions, no dependencies, so a reader can check them by hand.
"""
from __future__ import annotations

import math
import random
from typing import Dict, Sequence, Tuple


def wilson_ci(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score interval for k successes in n trials. (0.0, 1.0) when n == 0."""
    if n <= 0:
        return (0.0, 1.0)
    if not 0 <= k <= n:
        raise ValueError(f"need 0 <= k <= n, got k={k} n={n}")
    p = k / n
    z2 = z * z
    denom = 1 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k from n samples with c passes: 1 - C(n-c, k) / C(n, k).

    This is the estimator in the Codex paper; the naive 1 - (1 - c/n)**k is biased
    upward for small n. Returns 1.0 when fewer than k samples failed (every draw of k
    then contains a pass)."""
    if not 0 <= c <= n or k <= 0:
        raise ValueError(f"need 0 <= c <= n and k > 0, got n={n} c={c} k={k}")
    if k > n:
        raise ValueError(f"k={k} exceeds n={n} samples")
    if n - c < k:
        return 1.0
    # product form of C(n-c, k) / C(n, k), stable for large n
    prod = 1.0
    for i in range(n - c + 1, n + 1):
        prod *= 1.0 - k / i
    return 1.0 - prod


def pass_pow_k(p: float, k: int) -> float:
    """τ-bench pass^k: probability that all k independent trials pass, p**k."""
    if not 0.0 <= p <= 1.0 or k < 1:
        raise ValueError(f"need 0 <= p <= 1 and k >= 1, got p={p} k={k}")
    return p ** k


def fmt_ci(value: float, ci: Tuple[float, float]) -> str:
    """`0.96 [0.87, 0.99]` — the shape used in report.md."""
    return f"{value:.2f} [{ci[0]:.2f}, {ci[1]:.2f}]"


# ----------------------------------------------------------------- paired comparisons

def paired_bootstrap(a: Sequence[float], b: Sequence[float], *, n: int = 10_000, seed: int = 0) -> Dict:
    """Paired bootstrap of ``mean(b) - mean(a)`` over task-level samples.

    ``a[i]`` and ``b[i]`` are the two conditions' values for the SAME task i (per-task
    pass@1 or any score in [0, 1]). Resamples the per-task differences with replacement
    ``n`` times using ``random.Random(seed)`` so a reader can reproduce the interval.
    Returns ``{"delta", "ci95": [lo, hi], "n", "p_delta_le_0"}`` where ``ci95`` is the
    2.5th–97.5th percentile of the resampled means and ``p_delta_le_0`` the fraction
    of resamples with a non-positive delta (a one-sided bootstrap p-value for "b is
    better"). Identical arrays give delta 0 and ci95 [0, 0]."""
    if len(a) != len(b):
        raise ValueError(f"paired samples must have equal length, got {len(a)} and {len(b)}")
    m = len(a)
    if m == 0:
        raise ValueError("paired_bootstrap needs at least one pair")
    if n < 1:
        raise ValueError(f"need n >= 1 resamples, got {n}")
    diffs = [float(y) - float(x) for x, y in zip(a, b)]
    delta = sum(diffs) / m
    rng = random.Random(seed)
    means = []
    for _ in range(n):
        means.append(sum(rng.choices(diffs, k=m)) / m)
    means.sort()
    lo = means[max(0, math.ceil(0.025 * n) - 1)]
    hi = means[min(n - 1, math.ceil(0.975 * n) - 1)]
    p_le_0 = sum(1 for d in means if d <= 0.0) / n
    return {"delta": delta, "ci95": [lo, hi], "n": m, "p_delta_le_0": p_le_0}


def mcnemar(b: int, c: int) -> Dict:
    """Exact McNemar test on the discordant pairs of two paired binary outcomes.

    ``b`` = tasks where A passed and B failed, ``c`` = tasks where A failed and B
    passed (concordant pairs carry no information and are not needed). Under H0 the
    discordant count is Binomial(b + c, 1/2); the two-sided p-value is
    ``2 * P(X <= min(b, c))`` capped at 1, computed with ``math.comb`` (no scipy).
    Hand checks: ``mcnemar(3, 1)["p"] == 0.625``; ``mcnemar(10, 0)["p"] == 2 / 1024``.
    No discordant pairs -> p = 1.0."""
    if b < 0 or c < 0:
        raise ValueError(f"counts must be >= 0, got b={b} c={c}")
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "n_discordant": 0, "p": 1.0}
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return {"b": b, "c": c, "n_discordant": n, "p": min(1.0, 2.0 * tail)}


def fpr(fp: int, negatives: int) -> Tuple[float, Tuple[float, float]]:
    """False-positive rate over negative controls: ``(fp / negatives, wilson_ci)``.
    With no negatives the rate is reported as 0.0 with the uninformative interval
    (0.0, 1.0) — callers show the count so nobody reads 0.0 as evidence."""
    if negatives <= 0:
        return 0.0, (0.0, 1.0)
    if not 0 <= fp <= negatives:
        raise ValueError(f"need 0 <= fp <= negatives, got fp={fp} negatives={negatives}")
    return fp / negatives, wilson_ci(fp, negatives)
