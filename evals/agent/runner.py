"""agent-run / agent-validate: the Layer 6 run directory for the agent evals (Phase 7).

    python -m evals agent-validate --repo all [--only ids] [--mode auto|container|local] [--out DIR]
    python -m evals agent-run --repo <name|all> --model <id> --trials K --budget-usd N
                              [--only ids] [--mode ...] [--out DIR]

    load_agent_registry()   evals/registry/agent/<repo>.yaml, validated against repos.yaml
    run_validate(...)       the no-model gate over the selected tasks -> validity.json
    run_agent(...)          gate first, then tasks x trials through loop.run_trial, graded

Output, per run (`run_id` from `evals.run.make_run_id`):

    <out>/<run_id>/validity.json                 every ValidityResult, valid + quarantined ids
    <out>/<run_id>/samples.jsonl                 TrialResult.to_record per task x trial, appended
                                                 after every trial (a crash keeps what was paid
                                                 for); baselines as variant noop | reference
    <out>/<run_id>/summary.json                  overall + per eval_id: n, tasks, passed,
                                                 pass_rate, the four scores with Wilson CIs,
                                                 pass@k / pass^k, cost, tokens, denials,
                                                 budget_stops, quarantined, baselines; provenance;
                                                 `_reading`
    <out>/<run_id>/report.md                     the same as tables
    <out>/<run_id>/transcripts/<task>-<trial>.json  the loop's redacted transcript
    <out>/latest-agent.json                      {"run_id": ...} (agent-validate writes
                                                 latest-agent-validate.json)

Budget: per-trial USD cap = budget_usd / (valid tasks x trials); when the cumulative spend
reaches budget_usd the remaining trials are recorded with `stop_reason: budget` and
`failure_reason: "run budget exhausted"` without calling the model. A trial that ends with
any stop reason other than `done` is scored all-zero (`errors.trial` says why).

Sibling modules (W1 env, W2 loop, W3 tasks/graders) are imported at the top inside
try/except so this module imports on a branch where they do not exist yet; the names are
then None and tests install fakes with `monkeypatch.setattr(runner, "loop", fake)`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Union

import yaml

from ..metrics import fmt_ci, pass_at_k, pass_pow_k, wilson_ci
from ..registry import canary as registry_canary
from ..run import RESULTS, git_sha, make_run_id, toolkit_version
from . import baselines, repos
from .types import (STOP_BUDGET, STOP_DONE, STOP_ERROR, GradeContext, LoopResult, Provenance, Scores,
                    Task, TrialResult, Usage, ValidityResult)

try:  # W1
    from . import env  # type: ignore
except ImportError:  # pragma: no cover - sibling branch not merged yet
    env = None  # type: ignore
try:  # W2
    from . import loop  # type: ignore
except ImportError:  # pragma: no cover
    loop = None  # type: ignore
try:  # W3
    from . import tasks  # type: ignore
except ImportError:  # pragma: no cover
    tasks = None  # type: ignore
try:  # W3
    from . import graders  # type: ignore
except ImportError:  # pragma: no cover
    graders = None  # type: ignore

REPO = Path(__file__).resolve().parents[2]
AGENT_REGISTRY_DIR = REPO / "evals" / "registry" / "agent"
SCORE_NAMES = ("recall", "fix", "claim_fidelity", "scope_safety")
BUDGET_WARN_USD = 5.0   # the pilot allocation in EVALS-PLAN.md's budget schedule
RUN_BUDGET_EXHAUSTED = "run budget exhausted"

REGISTRY_REQUIRED = ("id", "version", "name", "repo", "commit", "catalogue", "description",
                     "source", "split", "graders", "metrics", "owner_agent", "canary")


# ----------------------------------------------------------------- registry

def load_agent_registry(registry_dir: Path = AGENT_REGISTRY_DIR, *,
                        repo_configs: Optional[Dict[str, repos.RepoConfig]] = None) -> Dict[str, Dict]:
    """Every `<repo>.yaml` under evals/registry/agent/, keyed by eval id, validated:
    id == security.agent.<repo>.v<version>, canary == CANARY.txt, split build, source
    real-codebase, and `commit` equal to repos.yaml's pin for `repo`."""
    want = registry_canary()
    cfgs = repo_configs if repo_configs is not None else repos.load_repos()
    out: Dict[str, Dict] = {}
    for y in sorted(Path(registry_dir).glob("*.yaml")):
        entry = yaml.safe_load(y.read_text()) or {}
        missing = [k for k in REGISTRY_REQUIRED if k not in entry]
        if missing:
            raise ValueError(f"{y}: missing {missing}")
        repo = entry["repo"]
        if entry["id"] != f"security.agent.{repo}.v{entry['version']}":
            raise ValueError(f"{y}: id {entry['id']!r} does not match repo/version")
        if entry["name"] != f"agent.{repo}":
            raise ValueError(f"{y}: name {entry['name']!r} must be agent.{repo}")
        if entry["canary"] != want:
            raise ValueError(f"{y}: canary differs from CANARY.txt")
        if entry["split"] != "build":
            raise ValueError(f"{y}: split must be build, got {entry['split']!r}")
        if entry["source"] != "real-codebase":
            raise ValueError(f"{y}: source must be real-codebase, got {entry['source']!r}")
        if repo not in cfgs:
            raise ValueError(f"{y}: repo {repo!r} is not in repos.yaml")
        if str(entry["commit"]) != cfgs[repo].commit:
            raise ValueError(f"{y}: commit {entry['commit']!r} differs from repos.yaml ({cfgs[repo].commit})")
        if list(entry["graders"]) != list(SCORE_NAMES):
            raise ValueError(f"{y}: graders must be {list(SCORE_NAMES)}")
        entry["_file"] = str(y.relative_to(REPO)) if y.is_relative_to(REPO) else str(y)
        out[entry["id"]] = entry
    return out


# ----------------------------------------------------------------- tasks

def _need(module, name: str):
    if module is None:
        raise RuntimeError(f"evals.agent.{name} is not available on this checkout")
    return module


def _filter_tasks(task_list: List[Task], only: Optional[Union[str, Iterable[str]]]) -> List[Task]:
    """`only`: comma-separated task ids, properties (P4) or eval ids. Uses W3's
    `tasks.filter_tasks` when it exists, else this fallback."""
    if not only:
        return list(task_list)
    if tasks is not None and hasattr(tasks, "filter_tasks"):
        return list(tasks.filter_tasks(task_list, only))
    keep = {s.strip() for s in (only.split(",") if isinstance(only, str) else only) if s.strip()}
    return [t for t in task_list if t.task_id in keep or t.property in keep or t.eval_id in keep]


def _load_tasks(selector: Union[str, Sequence[Task]], only=None, log=print):
    """-> (tasks, per_repo) where per_repo[name] = {"tasks": n} or {"error": ...}. A repo
    whose catalogue cannot be loaded (private clone without a token, a bad pin) is
    reported as quarantined-by-environment, not raised: the rest of the run proceeds."""
    per_repo: Dict[str, Dict[str, Any]] = {}
    if not isinstance(selector, str):
        all_tasks = list(selector)
        for t in all_tasks:
            per_repo.setdefault(t.repo, {"tasks": 0})["tasks"] += 1
        return _filter_tasks(all_tasks, only), per_repo
    tmod = _need(tasks, "tasks")
    all_tasks: List[Task] = []
    for cfg in repos.select_repos(selector):
        try:
            by_repo = tmod.load_all_tasks(cfg.name)
        except Exception as e:  # noqa: BLE001
            per_repo[cfg.name] = {"tasks": 0, "error": f"{type(e).__name__}: {str(e)[:200]}"}
            if log:
                log(f"repo {cfg.name}: could not load tasks ({type(e).__name__}); its tasks are "
                    f"quarantined by environment")
            continue
        ts = [t for lst in by_repo.values() for t in lst]
        per_repo[cfg.name] = {"tasks": len(ts)}
        all_tasks.extend(ts)
    return _filter_tasks(all_tasks, only), per_repo


def _env_factory(mode: str) -> Callable:
    emod = _need(env, "env")
    return lambda: emod.make_env(mode)


def _quarantined(results: List[ValidityResult], per_repo: Dict[str, Dict]) -> List[Dict[str, str]]:
    q = [{"task_id": r.task_id, "eval_id": r.eval_id, "reason": r.reason} for r in results if not r.valid]
    for name, info in per_repo.items():
        if info.get("error"):
            q.append({"task_id": f"{name}/*", "eval_id": f"security.agent.{name}.v1",
                      "reason": f"environment: {info['error']}"})
    return q


def _mode_of(results: List[ValidityResult], requested: str) -> str:
    modes = {r.mode for r in results if r.mode}
    return sorted(modes)[0] if len(modes) == 1 else (requested if not modes else "+".join(sorted(modes)))


def _rel(p: Path) -> str:
    p = p.resolve()
    return str(p.relative_to(REPO)) if p.is_relative_to(REPO) else str(p)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


# ----------------------------------------------------------------- agent-validate

def _validity_table(results: List[ValidityResult]) -> str:
    rows = [("task", "valid", "noop_fix", "reference_fix", "reason", "seconds")]
    for r in results:
        rows.append((r.task_id, "yes" if r.valid else "NO", str(r.noop_fix), str(r.reference_fix),
                     r.reason or "-", f"{r.seconds:.1f}"))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def _validity_report(doc: Dict) -> str:
    lines = [f"# Agent-eval validity gate · run `{doc['run_id']}`", "",
             f"Mode: {doc['mode']} · tasks: {len(doc['results'])} · valid: {len(doc['valid'])} · "
             f"quarantined: {len(doc['quarantined'])}", "",
             "noop must score fix=0 (the hidden test detects the mutation); reference must score "
             "fix=1 (the un-mutated tree passes). Anything else is quarantined and excluded from "
             "agent runs.", "",
             "| task | eval | valid | noop fix | reference fix | reason | s |", "|---|---|---|---|---|---|---|"]
    for r in doc["results"]:
        lines.append(f"| {r['task_id']} | {r['eval_id']} | {'yes' if r['valid'] else 'NO'} | "
                     f"{r['noop_fix']} | {r['reference_fix']} | {r['reason'] or '-'} | {r['seconds']:.1f} |")
    lines += ["", "## Per repo", "", "| repo | tasks | note |", "|---|---|---|"]
    for name, info in doc["per_repo"].items():
        lines.append(f"| {name} | {info.get('tasks', 0)} | {info.get('error', '-')} |")
    return "\n".join(lines) + "\n"


def run_validate(repo_selector: Union[str, Sequence[Task]], *, out_dir: Path = RESULTS, mode: str = "auto",
                 only=None, log=print, env_factory: Optional[Callable] = None) -> Dict:
    """The no-model gate over the selected tasks. Exit code 0 even with quarantines: the
    gate excludes, it does not fail."""
    out_dir = Path(out_dir)
    task_list, per_repo = _load_tasks(repo_selector, only, log)
    factory = env_factory or _env_factory(mode)
    results = baselines.validate(task_list, factory, log=log)
    run_id = make_run_id()
    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "run_id": run_id, "generated": _now(), "mode": _mode_of(results, mode),
        "selector": repo_selector if isinstance(repo_selector, str) else "tasks", "only": only,
        "toolkit_version": toolkit_version(), "git_sha": git_sha(),
        "results": [r.to_record() for r in results],
        "valid": [r.task_id for r in results if r.valid],
        "quarantined": _quarantined(results, per_repo),
        "per_repo": per_repo,
    }
    (run_dir / "validity.json").write_text(json.dumps(doc, indent=1, default=str))
    (run_dir / "report.md").write_text(_validity_report(doc))
    (out_dir / "latest-agent-validate.json").write_text(json.dumps(
        {"run_id": run_id, "path": _rel(run_dir), "generated": doc["generated"], "mode": doc["mode"]}, indent=1))
    if log:
        log(_validity_table(results))
        log(f"valid {len(doc['valid'])} · quarantined {len(doc['quarantined'])} · wrote {run_dir}")
    return {"run_id": run_id, "run_dir": str(run_dir), "valid": doc["valid"],
            "quarantined": doc["quarantined"], "mode": doc["mode"], "per_repo": per_repo}


# ----------------------------------------------------------------- agent-run

_FRONT_MATTER = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.S)


def agent_body(path: Path) -> str:
    """The agents/<name>.md body with its YAML front matter stripped."""
    return _FRONT_MATTER.sub("", path.read_text(), count=1).lstrip("\n")


def _provenance(task: Task, info, *, mode: str, model: str) -> Provenance:
    return Provenance(mode=getattr(info, "mode", None) or mode, repo=task.repo, repo_commit=task.commit,
                      toolkit_version=toolkit_version(), toolkit_sha=git_sha(), model=model,
                      image=getattr(info, "image", None), image_digest=getattr(info, "image_digest", None),
                      python=platform.python_version(), platform=platform.platform())


def _trial_result(task: Task, trial: int, *, variant: str, scores: Scores, lr: LoopResult,
                  prov: Provenance) -> TrialResult:
    return TrialResult(eval_id=task.eval_id, task_id=task.task_id, trial=trial, property=task.property,
                       agent=task.agent, source=task.source, scores=scores, stop_reason=lr.stop_reason,
                       failure_reason=lr.failure_reason, cost_usd=lr.cost_usd, usage=lr.usage,
                       tool_calls=lr.tool_calls, denials=list(lr.denials), elapsed_s=lr.elapsed_s,
                       provenance=prov, variant=variant)


def _empty_loop(model: str, stop_reason: str, failure_reason: str) -> LoopResult:
    return LoopResult(stop_reason=stop_reason, report=None, tool_calls=0, denials=[], usage=Usage(),
                      cost_usd=0.0, model=model, failure_reason=failure_reason)


def _baseline_rows(task: Task, vres: ValidityResult, prov: Provenance, model: str) -> List[TrialResult]:
    """The two baselines of one task, from the gate's fix scores (other scores 0, cost 0)."""
    out = []
    for variant, fix in (("noop", vres.noop_fix), ("reference", vres.reference_fix)):
        scores = Scores(fix=float(fix or 0.0), evidence={"fix": f"validity gate ({variant})"})
        out.append(_trial_result(task, 0, variant=variant, scores=scores,
                                 lr=_empty_loop(model, STOP_DONE, ""), prov=prov))
    return out


def run_agent(repo_selector: Union[str, Sequence[Task]], *, model: str, trials: int = 1, budget_usd: float,
              out_dir: Path = RESULTS, mode: str = "auto", only=None, log=print,
              env_factory: Optional[Callable] = None) -> Dict:
    """Gate first, then tasks x trials through `loop.run_trial`, graded by `graders.grade_all`.
    Returns the summary with `run_dir` added. `model` and `budget_usd` are required."""
    if not model:
        raise ValueError("model is required (no default: every run names what it spends on)")
    if budget_usd is None or not float(budget_usd) > 0:
        raise ValueError("budget_usd is required and must be > 0")
    if trials < 1:
        raise ValueError("trials must be >= 1")
    budget_usd = float(budget_usd)
    out_dir = Path(out_dir)
    lmod = _need(loop, "loop")
    gmod = _need(graders, "graders")

    # 0. refuse to start on a rejected credential (free call; before the 3-minute gate).
    # A test double for the loop that never spends may omit it; the real loop always has it.
    preflight = getattr(lmod, "preflight_auth", None)
    if preflight is not None:
        preflight()

    task_list, per_repo = _load_tasks(repo_selector, only, log)
    factory = env_factory or _env_factory(mode)

    # 1. the validity gate; quarantined tasks never reach the model
    vresults = baselines.validate(task_list, factory, log=log)
    by_id = {r.task_id: r for r in vresults}
    valid_tasks = [t for t in task_list if by_id[t.task_id].valid]
    quarantined = _quarantined(vresults, per_repo)
    run_mode = _mode_of(vresults, mode)

    run_id = make_run_id()
    run_dir = out_dir / run_id
    (run_dir / "transcripts").mkdir(parents=True, exist_ok=True)
    (run_dir / "validity.json").write_text(json.dumps({
        "run_id": run_id, "generated": _now(), "mode": run_mode,
        "results": [r.to_record() for r in vresults],
        "valid": [t.task_id for t in valid_tasks], "quarantined": quarantined, "per_repo": per_repo,
    }, indent=1, default=str))

    n_planned = len(valid_tasks) * trials
    per_trial_cap = budget_usd / n_planned if n_planned else 0.0
    if log:
        log(f"planned: {len(valid_tasks)} tasks x {trials} trials = {n_planned} trials, "
            f"per-trial cap ${per_trial_cap:.4f}, run cap ${budget_usd:.2f}, model {model}")
        if budget_usd > BUDGET_WARN_USD:
            log(f"warning: run cap ${budget_usd:.2f} exceeds the ${BUDGET_WARN_USD:.0f} pilot allocation "
                f"(EVALS-PLAN.md budget schedule); the monthly total must stay under $200")
        if quarantined:
            log(f"quarantined {len(quarantined)} task(s): " + ", ".join(q["task_id"] for q in quarantined))

    bodies: Dict[str, str] = {}
    rows: List[TrialResult] = []
    spent = 0.0
    last_info = None
    samples = run_dir / "samples.jsonl"
    samples.write_text("")

    def emit(tr: TrialResult) -> None:
        rows.append(tr)
        with samples.open("a") as fh:   # append per trial: a crash keeps what was paid for
            fh.write(json.dumps(tr.to_record(), sort_keys=True, default=str) + "\n")

    for task in valid_tasks:
        body = bodies.get(task.agent)
        if body is None:
            body = bodies[task.agent] = agent_body(REPO / task.agent)
        baseline_prov = _provenance(task, last_info, mode=run_mode, model=model)
        for tr in _baseline_rows(task, by_id[task.task_id], baseline_prov, model):
            emit(tr)
        for trial in range(1, trials + 1):
            if spent >= budget_usd:
                lr = _empty_loop(model, STOP_BUDGET, RUN_BUDGET_EXHAUSTED)
                scores = Scores(errors={"trial": RUN_BUDGET_EXHAUSTED})
                emit(_trial_result(task, trial, variant="agent", scores=scores, lr=lr,
                                   prov=_provenance(task, last_info, mode=run_mode, model=model)))
                continue
            e = factory()
            info = None
            lr: Optional[LoopResult] = None
            scores = Scores()
            try:
                info = e.reset(task)
                last_info = info
                lr = lmod.run_trial(task, e, model=model, budget_usd=per_trial_cap, agent_body=body, log=log)
                if lr.stop_reason == STOP_DONE:
                    diff = e.diff()
                    scores = gmod.grade_all(GradeContext(task=task, env=e, report=lr.report, diff=diff,
                                                         denials=list(lr.denials)))
                else:
                    scores = Scores(errors={"trial": lr.failure_reason or lr.stop_reason})
            except Exception as ex:  # noqa: BLE001 - one bad trial must not lose the run
                if lr is None:
                    lr = _empty_loop(model, STOP_ERROR, f"harness: {type(ex).__name__}: {str(ex)[:200]}")
                else:
                    lr.stop_reason, lr.failure_reason = STOP_ERROR, f"grading: {type(ex).__name__}: {str(ex)[:200]}"
                scores = Scores(errors={"trial": lr.failure_reason})
            finally:
                try:
                    e.close()
                except Exception:  # noqa: BLE001
                    pass
            spent += float(lr.cost_usd or 0.0)
            prov = _provenance(task, info, mode=run_mode, model=model)
            (run_dir / "transcripts" / f"{task.task_id}-{trial}.json").write_text(
                json.dumps({"task_id": task.task_id, "trial": trial, "stop_reason": lr.stop_reason,
                            "failure_reason": lr.failure_reason, "transcript": lr.transcript},
                           indent=1, default=str))
            emit(_trial_result(task, trial, variant="agent", scores=scores, lr=lr, prov=prov))
            if log:
                log(f"{task.task_id} trial {trial}: {'pass' if scores.passed else 'FAIL'} "
                    f"stop={lr.stop_reason} cost=${lr.cost_usd:.4f} spent=${spent:.4f}")

    summary = build_agent_summary([r.to_record() for r in rows], run_id=run_id, model=model, mode=run_mode,
                                  trials=trials, budget_usd=budget_usd, quarantined=quarantined,
                                  selected_evals=sorted({t.eval_id for t in task_list}))
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1, default=str))
    (run_dir / "report.md").write_text(render_agent_report(summary, [r.to_record() for r in rows]))
    (out_dir / "latest-agent.json").write_text(json.dumps(
        {"run_id": run_id, "path": _rel(run_dir), "generated": summary["generated"],
         "model": model, "mode": run_mode}, indent=1))
    if log:
        log(f"wrote {run_dir}")
    summary["run_dir"] = str(run_dir)
    return summary


# ----------------------------------------------------------------- summary

def _ci(k: float, n: int) -> Optional[List[float]]:
    return [round(x, 3) for x in wilson_ci(k, n)] if n else None


def _agent_block(agent_rows: List[Dict], baseline_rows: List[Dict], trials: int,
                 quarantined: List[Dict]) -> Dict:
    n = len(agent_rows)
    task_ids = {r["task_id"] for r in agent_rows}
    passed = sum(bool(r["passed"]) for r in agent_rows)
    b: Dict[str, Any] = {"n": n, "tasks": len(task_ids), "trials": trials, "passed": passed,
                         "pass_rate": round(passed / n, 3) if n else None, "pass_rate_ci95": _ci(passed, n)}
    for s in SCORE_NAMES:
        k = sum(float(r["scores"][s]) for r in agent_rows)
        b[s] = round(k / n, 3) if n else None
        b[f"{s}_ci95"] = _ci(k, n)
    per_task: Dict[str, List[bool]] = defaultdict(list)
    for r in agent_rows:
        per_task[r["task_id"]].append(bool(r["passed"]))
    full = [v for v in per_task.values() if len(v) == trials]
    b["pass_at_k"] = {str(k): (round(sum(pass_at_k(trials, sum(v), k) for v in full) / len(full), 3) if full else None)
                      for k in range(1, trials + 1)}
    b["pass_pow_k"] = {str(k): (round(sum(pass_pow_k(sum(v) / trials, k) for v in full) / len(full), 3) if full else None)
                       for k in range(1, trials + 1)}
    cost = sum(float(r["cost_usd"]) for r in agent_rows)
    b["cost_usd_total"] = round(cost, 6)
    b["cost_usd_per_task"] = round(cost / len(task_ids), 6) if task_ids else None
    tok = {f: sum(int(r["tokens"].get(f, 0)) for r in agent_rows)
           for f in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens")}
    tok["total"] = sum(tok.values())
    b["tokens"] = tok
    b["tool_calls_mean"] = round(sum(int(r["tool_calls"]) for r in agent_rows) / n, 2) if n else None
    b["denials"] = sum(len(r["denials"]) for r in agent_rows)
    b["budget_stops"] = sum(r["stop_reason"] == STOP_BUDGET for r in agent_rows)
    b["errors"] = sum(r["stop_reason"] == STOP_ERROR for r in agent_rows)
    b["quarantined"] = quarantined
    noop = [float(r["scores"]["fix"]) for r in baseline_rows if r["variant"] == "noop"]
    ref = [float(r["scores"]["fix"]) for r in baseline_rows if r["variant"] == "reference"]
    b["baselines"] = {"noop_fix_mean": round(sum(noop) / len(noop), 3) if noop else None,
                      "reference_fix_mean": round(sum(ref) / len(ref), 3) if ref else None}
    return b


def _provenance_block(rows: List[Dict], *, mode: str, model: str) -> Dict:
    per_repo: Dict[str, Dict] = {}
    for r in rows:
        p = r["provenance"]
        d = per_repo.setdefault(p["repo"], {"commit": p["repo_commit"], "image": None, "image_digest": None})
        if p.get("image_digest") and not d["image_digest"]:
            d["image"], d["image_digest"] = p.get("image"), p.get("image_digest")
    return {"mode": mode, "model": model, "toolkit_version": toolkit_version(), "toolkit_sha": git_sha(),
            "python": platform.python_version(), "platform": platform.platform(), "repos": per_repo}


def build_agent_summary(rows: List[Dict], *, run_id: str, model: str, mode: str, trials: int,
                        budget_usd: float, quarantined: List[Dict], selected_evals: List[str]) -> Dict:
    agent_rows = [r for r in rows if r["variant"] == "agent"]
    base_rows = [r for r in rows if r["variant"] != "agent"]
    evals: Dict[str, Dict] = {}
    for eid in sorted(set(selected_evals) | {r["eval_id"] for r in rows}):
        q = [x for x in quarantined if x.get("eval_id") == eid]
        evals[eid] = {"repo": eid.split(".")[2] if eid.count(".") >= 3 else None,
                      **_agent_block([r for r in agent_rows if r["eval_id"] == eid],
                                     [r for r in base_rows if r["eval_id"] == eid], trials, q)}
    overall = _agent_block(agent_rows, base_rows, trials, quarantined)
    return {
        "run_id": run_id, "generated": _now(), "model": model, "mode": mode, "trials": trials,
        "budget_usd": budget_usd, "cost_usd_total": overall["cost_usd_total"],
        "toolkit_version": toolkit_version(), "git_sha": git_sha(),
        "provenance": _provenance_block(rows, mode=mode, model=model),
        "overall": overall, "evals": evals,
        "_reading": {
            "n": "agent trials = valid tasks x trials (baseline rows are not counted); quarantined "
                 "tasks never ran",
            "passed": "trials where all four scores are 1.0; pass_rate = passed / n, *_ci95 is the "
                      "Wilson score interval over n",
            "recall/fix/claim_fidelity/scope_safety": "mean of the score over n, with a Wilson CI "
                                                      "treating the sum as successes over n",
            "pass_at_k": "mean over tasks with all `trials` rows of the unbiased pass@k estimator, "
                         "k = 1..trials",
            "pass_pow_k": "mean over the same tasks of p**k (tau-bench consistency), k = 1..trials",
            "cost_usd_total / cost_usd_per_task": "measured from usage x prices.yaml; per task = "
                                                  "total / distinct tasks, all trials included",
            "tokens": "input, output, cache_read, cache_write summed over agent trials",
            "budget_stops": "trials ended by the per-trial guard or the run cap "
                            "(failure_reason 'run budget exhausted'); scored 0",
            "errors": "trials ended by a harness/API error; scored 0",
            "denials": "denied or malformed model actions across trials (scope-safety events)",
            "quarantined": "tasks the validity gate excluded, with the categorical reason; a "
                           "`<repo>/*` entry means the repo's catalogue could not be loaded",
            "baselines": "noop_fix_mean must be 0 and reference_fix_mean 1 over the valid tasks "
                         "(the gate guarantees it); shown so the agent is read against them",
            "mode": "container | local; local runs are labelled and not comparable to container runs",
        },
    }


# ----------------------------------------------------------------- report

def _fmt(b: Dict, s: str) -> str:
    return fmt_ci(b[s], b[f"{s}_ci95"]) if b.get(s) is not None else "—"


def render_agent_report(summary: Dict, rows: List[Dict]) -> str:
    o = summary["overall"]
    trials = summary["trials"]
    kk = str(trials)
    lines = [f"# Agent evals — security-agents {summary['toolkit_version']} · run `{summary['run_id']}`", "",
             f"Model: `{summary['model']}` · mode: {summary['mode']} · trials: {trials} · "
             f"tasks: {o['tasks']} · samples: {o['n']} · passed: {o['passed']} · "
             f"cost: ${summary['cost_usd_total']:.4f} of ${summary['budget_usd']:.2f} · "
             f"budget stops: {o['budget_stops']} · quarantined: {len(o['quarantined'])}", "",
             f"**Pass rate {_fmt(o, 'pass_rate')} · pass@{kk} {o['pass_at_k'].get(kk)} · "
             f"pass^{kk} {o['pass_pow_k'].get(kk)} · ${o['cost_usd_per_task'] or 0:.4f}/task**", "",
             "A trial passes when recall, fix, claim fidelity and scope safety are all 1.0. CIs are "
             "Wilson 95%. Baselines: noop fix mean "
             f"{o['baselines']['noop_fix_mean']}, reference fix mean {o['baselines']['reference_fix_mean']}.", "",
             f"| eval | tasks | n | pass rate | recall | fix | claim | scope | pass@{kk} | pass^{kk} | $/task | budget stops | quarantined |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for eid, b in summary["evals"].items():
        lines.append(f"| {eid} | {b['tasks']} | {b['n']} | {_fmt(b, 'pass_rate')} | {_fmt(b, 'recall')} | "
                     f"{_fmt(b, 'fix')} | {_fmt(b, 'claim_fidelity')} | {_fmt(b, 'scope_safety')} | "
                     f"{b['pass_at_k'].get(kk)} | {b['pass_pow_k'].get(kk)} | "
                     f"{b['cost_usd_per_task'] if b['cost_usd_per_task'] is not None else '—'} | "
                     f"{b['budget_stops']} | {len(b['quarantined'])} |")
    lines += ["", "## Trials", "",
              "| task | trial | recall | fix | claim | scope | passed | stop | cost | tool calls | denials |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        if r["variant"] != "agent":
            continue
        s = r["scores"]
        lines.append(f"| {r['task_id']} | {r['trial']} | {s['recall']} | {s['fix']} | {s['claim_fidelity']} | "
                     f"{s['scope_safety']} | {'pass' if r['passed'] else 'FAIL'} | {r['stop_reason']} | "
                     f"${r['cost_usd']:.4f} | {r['tool_calls']} | {len(r['denials'])} |")
    lines += ["", "## Quarantined", ""]
    if o["quarantined"]:
        lines += ["| task | reason |", "|---|---|"]
        lines += [f"| {q['task_id']} | {q['reason']} |" for q in o["quarantined"]]
    else:
        lines.append("None.")
    p = summary["provenance"]
    lines += ["", "## Provenance", "",
              f"- mode: {p['mode']} · model: `{p['model']}` · toolkit {p['toolkit_version']} @ {p['toolkit_sha']}",
              f"- python {p['python']} · {p['platform']}"]
    for name, d in p["repos"].items():
        lines.append(f"- {name}: commit `{d['commit']}` · image {d['image'] or '—'} · digest {d['image_digest'] or '—'}")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- CLI entry points

def _common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--repo", required=True, metavar="NAME", help="repo name from repos.yaml, comma list, or all")
    ap.add_argument("--only", default=None, help="comma-separated task ids or properties")
    ap.add_argument("--mode", default="auto", choices=("auto", "container", "local"))
    ap.add_argument("--out", default=str(RESULTS), metavar="DIR")


def main_validate(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals agent-validate",
                                 description="No-model validity gate: noop must fail, reference must pass.")
    _common(ap)
    args = ap.parse_args(argv)
    run_validate(args.repo, out_dir=Path(args.out), mode=args.mode, only=args.only)
    return 0


def main_run(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals agent-run",
                                 description="Run one agent spec over the repo's tasks, gate first.")
    _common(ap)
    ap.add_argument("--model", required=True, help="model id (no default)")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--budget-usd", required=True, type=float, dest="budget_usd",
                    help="run cap in USD (no default); per-trial cap = this / (tasks x trials)")
    args = ap.parse_args(argv)
    try:
        run_agent(args.repo, model=args.model, trials=args.trials, budget_usd=args.budget_usd,
                  out_dir=Path(args.out), mode=args.mode, only=args.only)
    except loop.AuthPreflightError as e:
        print(f"refusing to start: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main_run())
