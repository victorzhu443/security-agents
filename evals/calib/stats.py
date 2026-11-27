"""The statistics kit the calibration reports use (Phase 1, W-D) — used, not just cited.

    power_note(n, p0, delta)      one sentence: the power of a one-sample proportion test
                                  with n tasks to detect a `delta` change from p0, plus the n
                                  needed for 80 % (normal approximation, two-sided)
    per_task_pass(records)        trials -> per-task pass@1 (the task is the unit; k trials of
                                  one task are correlated and never enter a test as k samples)
    compare(run_a, run_b)         paired bootstrap + McNemar on the task intersection of two runs

Pure functions over dicts; no scipy. The normal CDF is `math.erf`, its inverse a bisection.
"""
from __future__ import annotations

import math
from typing import Dict, List, Sequence

from ..metrics import mcnemar, paired_bootstrap


def norm_cdf(x: float) -> float:
    return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))


def norm_ppf(q: float) -> float:
    """Inverse normal CDF by bisection (12 significant digits is plenty for a power note)."""
    if not 0.0 < q < 1.0:
        raise ValueError(f"need 0 < q < 1, got {q}")
    lo, hi = -40.0, 40.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if norm_cdf(mid) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def power(n: int, p0: float, delta: float, *, alpha: float = 0.05) -> float:
    """Power of the two-sided one-sample z-test for a proportion (normal approximation):
    H0 p = p0 against the alternative p1 = p0 + delta, with n tasks."""
    if n <= 0:
        return 0.0
    p1 = min(1.0 - 1e-9, max(1e-9, p0 + delta))
    p0 = min(1.0 - 1e-9, max(1e-9, p0))
    z = norm_ppf(1 - alpha / 2)
    se0 = math.sqrt(p0 * (1 - p0) / n)
    se1 = math.sqrt(p1 * (1 - p1) / n)
    d = abs(p1 - p0)
    return norm_cdf((d - z * se0) / se1) + norm_cdf((-d - z * se0) / se1)


def n_for_power(p0: float, delta: float, *, alpha: float = 0.05, target: float = 0.8) -> int:
    """Tasks needed for `target` power (same approximation, solved in closed form)."""
    p1 = min(1.0 - 1e-9, max(1e-9, p0 + delta))
    p0 = min(1.0 - 1e-9, max(1e-9, p0))
    d = abs(p1 - p0)
    if d <= 0:
        return 0
    za, zb = norm_ppf(1 - alpha / 2), norm_ppf(target)
    return math.ceil(((za * math.sqrt(p0 * (1 - p0)) + zb * math.sqrt(p1 * (1 - p1))) / d) ** 2)


def power_note(n: int, p0: float, delta: float, *, alpha: float = 0.05) -> str:
    """A sentence for the card and the summary, e.g. "With 35 tasks a two-sided test at
    alpha 0.05 has 39% power to detect a 15-point change from 0.50 (normal approximation);
    about 85 tasks are needed for 80%." """
    pw = power(n, p0, delta, alpha=alpha)
    need = n_for_power(p0, delta, alpha=alpha)
    return (f"With {n} tasks a two-sided test at alpha {alpha:g} has {pw * 100:.0f}% power to detect a "
            f"{abs(delta) * 100:.0f}-point change from {p0:.2f} (normal approximation); "
            f"about {need} tasks are needed for 80%.")


def clustered_stderr(per_task: Dict[str, Sequence[float]]) -> float:
    """Miller 2024 / Inspect `stderr(cluster=task)`: collapse each task's trials to their mean,
    then the standard error of the mean over tasks, sd(task means) / sqrt(T) with the sample
    (T - 1) variance. 0.0 for fewer than two tasks or all-equal task means."""
    means = [sum(v) / len(v) for v in per_task.values() if len(v)]
    t = len(means)
    if t < 2:
        return 0.0
    m = sum(means) / t
    var = sum((x - m) ** 2 for x in means) / (t - 1)
    return math.sqrt(var / t)


def per_task_pass(records: Sequence[Dict], *, key: str = "reward") -> Dict[str, float]:
    """Per-task pass@1 from trial records: the fraction of a task's trials whose `rewards[key]`
    is 1.0. A trial with no rewards (harness error) counts as a failure. Records are the
    `parse_job` shape ({task_id, rewards}); a `passed` boolean is honoured when `key` is
    "passed" (samples.jsonl shape)."""
    hits: Dict[str, List[float]] = {}
    for r in records:
        tid = str(r.get("task_id"))
        if key == "passed":
            ok = bool(r.get("passed"))
        else:
            rewards = r.get("rewards") or {}
            v = rewards.get(key)
            ok = v is not None and float(v) >= 1.0
        hits.setdefault(tid, []).append(1.0 if ok else 0.0)
    return {tid: sum(v) / len(v) for tid, v in sorted(hits.items())}


def compare(run_a: Dict[str, float], run_b: Dict[str, float], *, n_boot: int = 10_000, seed: int = 0) -> Dict:
    """Paired comparison of two runs' per-task values on the tasks both ran. `delta` is
    mean(B) - mean(A). McNemar's `b` counts tasks where A > B, `c` tasks where B > A
    (for binary per-task values this is exactly McNemar's discordant table; for pass@1
    fractions it is the sign test on the paired differences)."""
    ids = sorted(set(run_a) & set(run_b))
    if not ids:
        return {"n": 0, "tasks": [], "only_a": sorted(set(run_a) - set(run_b)),
                "only_b": sorted(set(run_b) - set(run_a)), "bootstrap": None, "mcnemar": None,
                "mean_a": None, "mean_b": None}
    a = [float(run_a[t]) for t in ids]
    b = [float(run_b[t]) for t in ids]
    b_cnt = sum(1 for x, y in zip(a, b) if x > y)
    c_cnt = sum(1 for x, y in zip(a, b) if y > x)
    return {"n": len(ids), "tasks": ids,
            "only_a": sorted(set(run_a) - set(run_b)), "only_b": sorted(set(run_b) - set(run_a)),
            "mean_a": sum(a) / len(a), "mean_b": sum(b) / len(b),
            "bootstrap": paired_bootstrap(a, b, n=n_boot, seed=seed), "mcnemar": mcnemar(b_cnt, c_cnt)}
