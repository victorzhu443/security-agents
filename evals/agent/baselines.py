"""The two baselines and the no-model validity gate (EVALS-PLAN.md Layer 7 rule 2, Phase 7).

    validate_task(task, env)        noop must score fix=0, reference must score fix=1
    validate(tasks, env_factory)    the gate over a task list, one fresh Env per task

Fully offline: no model, no key, no network beyond the clone `env.reset` makes. The two
baselines are exactly what the report later shows next to the agent (Layer 6 "baselines
in the report"):

    noop        the environment as the agent first sees it (mutation applied, no edits);
                the hidden test must FAIL here, otherwise the test does not detect the
                mutation and the task cannot tell a fix from doing nothing
    reference   the mutated file restored from `task.commit` (`git checkout <commit> -- file`
                in the clone, which undoes the mutation commit that `reset` made); the
                hidden test must PASS here, otherwise the task is unsolvable as written

A task failing either check is quarantined with a categorical reason and excluded from
the agent run by `runner.run_agent`. The gate's job is to exclude, never to fail a run.

Reference reuse (optimisation, `validate(..., reuse_reference=True)`): the reference tree
is the same un-mutated tree for every task of one repo at one commit, so the reference
result is identical for every task that shares `(repo, commit, hidden_test)`. `validate`
computes it once per such group and reuses it for the rest of the group; the value is
still recorded per task in `ValidityResult.reference_fix`. Pass `reuse_reference=False`
to run the reference test for every task.

Lazy imports: `FixGrader` is W3's (graders.py) and is imported inside `_fix_grader()` so
this module imports without it; tests monkeypatch `_fix_grader` and `_restore_reference`.
"""
from __future__ import annotations

import subprocess
import time
from typing import Callable, Dict, List, Optional, Tuple

from .types import Env, GradeContext, GradeResult, Task, ValidityResult

REASON_NOOP_PASSES = "noop passes (hidden test does not detect the mutation)"
REASON_REFERENCE_FAILS = "reference fails (un-mutated tree does not pass)"


def _fix_grader():
    """The fix grader (W3). Imported lazily; tests replace this factory."""
    from .graders import FixGrader
    return FixGrader()


def _restore_reference(task: Task, env: Env) -> None:
    """Put the un-mutated file back: `git checkout <task.commit> -- <task.file>` in the clone.

    `reset` committed the mutation on top of `task.commit`, so checking the file out from
    `task.commit` restores exactly the reference fix and nothing else."""
    if env.workdir is None:
        raise RuntimeError("env has no workdir (reset not called?)")
    subprocess.run(["git", "-C", str(env.workdir), "checkout", task.commit, "--", task.file],
                   capture_output=True, text=True, check=True, timeout=120)


def _fix_score(task: Task, env: Env) -> GradeResult:
    return _fix_grader().grade(GradeContext(task=task, env=env, report=None, diff="", denials=[]))


def validate_task(task: Task, env: Env, *, reference_fix: Optional[float] = None) -> ValidityResult:
    """Run the gate for one task in `env` (closed on return, even on error).

    `reference_fix`: a value already known for this task's (repo, commit, hidden_test)
    group; when given, the reference step is skipped and the value recorded as is."""
    t0 = time.perf_counter()
    noop: Optional[float] = None
    ref: Optional[float] = reference_fix
    mode = getattr(env, "mode", "") or ""
    reason = ""
    try:
        env.reset(task)
        mode = getattr(env, "mode", mode) or mode
        r = _fix_score(task, env)
        if r.error:
            reason = f"error: noop grade: {r.error}"
        else:
            noop = float(r.value)
            if ref is None:
                _restore_reference(task, env)
                r2 = _fix_score(task, env)
                if r2.error:
                    reason = f"error: reference grade: {r2.error}"
                else:
                    ref = float(r2.value)
    except subprocess.TimeoutExpired as e:
        reason = f"error: timeout: {e}"
    except Exception as e:  # noqa: BLE001 - the gate records, it never raises per task
        reason = f"error: {type(e).__name__}: {str(e)[:200]}"
    finally:
        try:
            env.close()
        except Exception:  # noqa: BLE001
            pass
    if not reason:
        if noop != 0.0:
            reason = REASON_NOOP_PASSES
        elif ref != 1.0:
            reason = REASON_REFERENCE_FAILS
    valid = not reason
    return ValidityResult(task_id=task.task_id, eval_id=task.eval_id, valid=valid,
                          noop_fix=noop, reference_fix=ref, reason=reason,
                          seconds=round(time.perf_counter() - t0, 3), mode=mode)


def _group_key(task: Task) -> Tuple[str, str, str]:
    return (task.repo, task.commit, task.hidden_test)


def validate(tasks: List[Task], env_factory: Callable[[], Env], *, log=None,
             reuse_reference: bool = True) -> List[ValidityResult]:
    """The gate over `tasks`; `env_factory()` returns a fresh Env for each task."""
    out: List[ValidityResult] = []
    known_ref: Dict[Tuple[str, str, str], float] = {}
    for task in tasks:
        key = _group_key(task)
        cached = known_ref.get(key) if reuse_reference else None
        try:
            env = env_factory()
        except Exception as e:  # noqa: BLE001 - e.g. "container" mode without docker
            res = ValidityResult(task_id=task.task_id, eval_id=task.eval_id, valid=False,
                                 noop_fix=None, reference_fix=None,
                                 reason=f"error: env: {type(e).__name__}: {str(e)[:200]}", mode="")
        else:
            res = validate_task(task, env, reference_fix=cached)
        # Cache the reference verdict only when it came from a real run this round and the
        # noop step did not error (an error leaves the group uncached: it is retried).
        if reuse_reference and cached is None and res.reference_fix is not None and not res.reason.startswith("error"):
            known_ref[key] = res.reference_fix
        out.append(res)
        if log:
            log(f"validate {task.task_id}: {'valid' if res.valid else 'QUARANTINE'} "
                f"noop={res.noop_fix} reference={res.reference_fix} {res.reason} ({res.seconds}s)")
    return out
