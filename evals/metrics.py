"""The metrics vocabulary the labs' eval reports share (EVALS-PLAN.md Layer 6).

    wilson_ci(k, n)        95% interval for a proportion k/n (Wilson score; no 0-width
                           intervals at 0/n or n/n, unlike the normal approximation)
    pass_at_k(n, c, k)     P(at least one of k samples passes), estimated without bias
                           from n samples of which c passed (Chen et al. 2021, Codex)
    pass_pow_k(p, k)       P(all k samples pass) = p**k — τ-bench's pass^k, the
                           consistency metric: how reliably, not how often

All pure functions, no dependencies, so a reader can check them by hand.
"""
from __future__ import annotations

import math
from typing import Tuple


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
