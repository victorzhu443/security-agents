"""calib-*: the CLI of the calibration pipeline — wraps `harbor run`, turns Harbor's job
results into the Layer-6 summary / report, and owns the splits, seal and comparisons (W-D).

    python -m evals calib-ingest ...                       W-A's ingest (delegated)
    python -m evals calib-build [--dry-run] [--with-sast]  W-B's build_all (delegated)
    python -m evals calib-validate [--dry-run]             nop + oracle jobs over tasks/ (the validity gate)
    python -m evals calib-split [--seed N] [--check] [--unseal-test]
    python -m evals calib-run --model ID --trials K --budget-usd N --condition class-blind|class-aware
                              --split train|validation|test [--ablation no_verifier] [--anchor]
                              [--baseline NAME] [--env docker|modal|daytona] [--unseal-test] [--dry-run]
    python -m evals calib-compare A B                      paired bootstrap + McNemar on two runs

Refusals (exit 2, nothing written, nothing spent): `calib-run` without `--model` (unless the
baseline is a control or a SAST tool, which call no model) or without a positive
`--budget-usd`; `--split test` without `--unseal-test`; a disabled baseline without
`--allow-disabled`; `--anchor` when the registry's anchor list is empty. `--dry-run` prints the
exact `harbor run` argv and writes nothing. Harbor is invoked as a subprocess — this module never
imports `harbor`, so the unit tests run without it, without docker and without a key.

Spending: Harbor itself caps nothing. Our agent receives `--ak budget_usd=<per-trial cap>`
(= budget / (tasks x trials)) and refuses to start a trial above it; the summary's `budget`
block records the cap, the measured spend and the rule "model calls are the whole $200/month;
sandbox time is $0 within the Modal/Daytona credits" (amendment A5).

Smoke of runner + baselines once docker (colima) is up — never run by tests or by this module:
    harbor run -d terminal-bench-sample@2.0 -a <baseline>

Run directory (`evals/results/<run_id>/`, `run_id` from `evals.run.make_run_id`):
    plan.json        the argv, baseline, condition, split, cap — written before harbor starts
    jobs/<job>/      Harbor's job dir (result.json, per-trial dirs) — Harbor writes it
    samples.jsonl    one record per trial: rewards, per-criterion details, cost, tokens, outcome
    summary.json     overall + per split + per stratum + per contamination bin + tasks + _reading
    report.md        the same as tables: train / validation / test and pre / post side by side
`evals/results/latest-calib.json` points at the last run.

Rewards (amendment A1): the verifier is a RewardKit tree, so `verifier_result.rewards` holds
exactly `evals.calib.REWARD_KEYS` and the per-criterion detail (`fix/hidden_test_passes` with
`reasoning: "rc=<n>"`, the "not-applicable" 1.0 of recall on a negative or fp on a positive) is
in `<trial>/verifier/reward-details.json`. `parse_job` reads both; the summary aggregates recall
over positives and fp over negatives only, by task metadata; the validity gate reads the rc
values from the details.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import yaml

from ..agent.types import SCORE_NAMES, SPLITS, Task, ValidityResult
from ..metrics import fmt_ci, fpr, pass_at_k, pass_pow_k, wilson_ci
from ..registry import canary as registry_canary
from ..run import RESULTS, git_sha, make_run_id, toolkit_version
from . import (CALIB_DIR, CANDIDATES_FILE, CLASS_NAME, EVAL_ID, HARBOR_VERSION, REGISTRY_FILE, REPO,
               REWARD_DIMENSIONS, SPLITS_DIR, TASKS_DIR, TASKS_JSONL)
from . import split as splitmod
from .stats import clustered_stderr, compare, per_task_pass, power_note

BASELINES_FILE = CALIB_DIR / "baselines.yaml"
CLASS_BLIND, CLASS_AWARE = "class-blind", "class-aware"     # mirror prompts.py (imported lazily when present)
MODES = (CLASS_BLIND, CLASS_AWARE)
ABLATIONS = ("no_verifier",)
ENVS = ("docker", "modal", "daytona")
BASELINE_KINDS = ("ours", "generic", "control", "sast")
MODEL_FREE_KINDS = ("control", "sast")
BUDGET_NOTE = "model calls are the whole $200/month; sandbox time is $0 within the Modal/Daytona credits"
POWER_DELTA = 0.15                                           # the plan's "15-point difference"

REGISTRY_REQUIRED = ("id", "version", "name", "property", "cwe", "description", "source", "tasks", "tasks_dir",
                     "harbor_version", "splits", "primary_metric", "secondary_metrics", "graders", "prompt_hashes",
                     "conditions", "cutoffs", "anchor", "exclusions", "owner_agent", "canary")
SPLITS_REQUIRED = ("seed", "fractions", "counts", "test_hash", "sealed_at", "manifests")
BASELINE_REQUIRED = ("name", "kind", "harbor_agent", "enabled")
_RC_RE = re.compile(r"\brc\s*=\s*(-?\d+)")


class CalibError(RuntimeError):
    """A refusal: the command cannot proceed as asked (exit 2, nothing written)."""


class SealedTestError(CalibError):
    """`--split test` without `--unseal-test`."""


# ----------------------------------------------------------------- registry and baselines

def load_calib_registry(path: Path = REGISTRY_FILE) -> Dict:
    """evals/registry/calib/<class>.yaml, validated against evals/registry/calib/README.md."""
    path = Path(path)
    entry = yaml.safe_load(path.read_text()) or {}
    missing = [k for k in REGISTRY_REQUIRED if k not in entry]
    if missing:
        raise ValueError(f"{path}: missing {missing}")
    if entry["id"] != f"security.{entry['name']}.v{entry['version']}":
        raise ValueError(f"{path}: id {entry['id']!r} does not match name/version")
    if entry["canary"] != registry_canary():
        raise ValueError(f"{path}: canary differs from CANARY.txt")
    smissing = [k for k in SPLITS_REQUIRED if k not in (entry["splits"] or {})]
    if smissing:
        raise ValueError(f"{path}: splits block missing {smissing}")
    for cond in (CLASS_BLIND, CLASS_AWARE):
        if set((entry["prompt_hashes"] or {}).get(cond, {})) != {"system", "user"}:
            raise ValueError(f"{path}: prompt_hashes.{cond} must have system and user")
    entry["_file"] = str(path.relative_to(REPO)) if path.is_relative_to(REPO) else str(path)
    return entry


def load_baselines(path: Path = BASELINES_FILE) -> List[Dict]:
    """The baseline list — data, never a constant (CONTRACTS.md A4). Each entry normalised to
    {name, kind, harbor_agent, model, enabled, version, network, agent_kwargs, note, ...sast keys}."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    rows = data.get("baselines")
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"{path}: `baselines` must be a non-empty list")
    out, seen = [], set()
    for row in rows:
        missing = [k for k in BASELINE_REQUIRED if k not in row]
        if missing:
            raise ValueError(f"{path}: baseline {row.get('name')!r} missing {missing}")
        if row["kind"] not in BASELINE_KINDS:
            raise ValueError(f"{path}: baseline {row['name']!r}: kind must be one of {BASELINE_KINDS}")
        if row["name"] in seen:
            raise ValueError(f"{path}: duplicate baseline {row['name']!r}")
        if row["kind"] == "sast":
            for k in ("invocation", "adapter"):
                if not row.get(k):
                    raise ValueError(f"{path}: sast baseline {row['name']!r} needs {k}")
        seen.add(row["name"])
        b = dict(row)
        b.setdefault("model", None)
        b["enabled"] = bool(b["enabled"])
        b["version"] = str(b.get("version") or "")
        b.setdefault("network", "no-network")
        b["agent_kwargs"] = {str(k): str(v) for k, v in (b.get("agent_kwargs") or {}).items()}
        b.setdefault("note", "")
        out.append(b)
    return out


def baseline_by_name(name: str, baselines: Sequence[Dict], *, allow_disabled: bool = False) -> Dict:
    for b in baselines:
        if b["name"] == name:
            if not b["enabled"] and not allow_disabled:
                raise CalibError(f"baseline {name!r} is disabled in baselines.yaml ({b.get('note') or 'no note'}); "
                                 "pass --allow-disabled to run it anyway")
            return b
    raise CalibError(f"no baseline named {name!r} in baselines.yaml (have: {', '.join(b['name'] for b in baselines)})")


# ----------------------------------------------------------------- conditions (prompts.py seam)

def condition_name(mode: str, ablation: Optional[str]) -> str:
    """"class-blind" | "class-aware" | "<mode>+no_verifier" — via prompts.Condition when present."""
    if mode not in MODES:
        raise CalibError(f"condition must be one of {MODES}, got {mode!r}")
    if ablation is not None and ablation not in ABLATIONS:
        raise CalibError(f"ablation must be one of {ABLATIONS}, got {ablation!r}")
    try:
        from ..agent.prompts import Condition   # W-C
        return Condition(mode=mode, verifier=ablation != "no_verifier").name
    except ImportError:
        return mode if ablation is None else f"{mode}+{ablation}"


def condition_requires(ablation: Optional[str]) -> Tuple[str, ...]:
    """The scores `passed` requires: all four, minus claim_fidelity under no_verifier."""
    if ablation == "no_verifier":
        return tuple(s for s in SCORE_NAMES if s != "claim_fidelity")
    return tuple(SCORE_NAMES)


def _prompt_hashes_for(condition: str, tasks: Sequence[Task]) -> Dict[str, str]:
    """{"system", "user"} of the prompts this run used, from prompts.prompt_hashes when the
    module exists and a task is available; {} otherwise (recorded as unpinned)."""
    try:
        from ..agent.prompts import Condition, prompt_hashes
    except ImportError:
        return {}
    if not tasks:
        return {}
    try:
        return dict(prompt_hashes(tasks[0], Condition.parse(condition)))
    except Exception:  # noqa: BLE001 - a prompts failure must not lose the run's numbers
        return {}


# ----------------------------------------------------------------- harbor argv (pure)

def harbor_argv(*, dataset_dir: Path, agent: str, model: Optional[str], trials: int, concurrency: int,
                jobs_dir: Path, job_name: str, agent_kwargs: Dict[str, str], extra: Sequence[str] = ()) -> List[str]:
    """`harbor run -p <dataset_dir> -a <agent> [-m <model>] -k <trials> -n <concurrency> -o <jobs_dir>
    --job-name <name> --ak k=v ... <extra>`. Pure: builds the argv, runs nothing."""
    argv = ["harbor", "run", "-p", str(dataset_dir), "-a", str(agent)]
    if model:
        argv += ["-m", str(model)]
    argv += ["-k", str(int(trials)), "-n", str(int(concurrency)), "-o", str(jobs_dir), "--job-name", str(job_name)]
    for k in sorted(agent_kwargs):
        argv += ["--ak", f"{k}={agent_kwargs[k]}"]
    argv += [str(x) for x in extra]
    return argv


# ----------------------------------------------------------------- job results

def _parse_dt(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_reward_details(obj: Any) -> Dict[str, Dict[str, Any]]:
    """Tolerant reader of RewardKit's reward-details.json: every object that carries a numeric
    `score` is one criterion, named by its `name`/`criterion` key or by the key it hangs under;
    `reasoning` is kept and an `rc=<n>` inside it parsed to `rc`. -> {name: {score, reasoning, rc}}."""
    out: Dict[str, Dict[str, Any]] = {}

    def visit(node: Any, parent_key: Optional[str]) -> None:
        if isinstance(node, dict):
            score = node.get("score")
            if isinstance(score, (int, float)) and not isinstance(score, bool):
                name = node.get("name") or node.get("criterion") or node.get("id") or parent_key
                if name:
                    reasoning = str(node.get("reasoning") or node.get("reason") or "")
                    m = _RC_RE.search(reasoning)
                    out[str(name)] = {"score": float(score), "reasoning": reasoning,
                                      "rc": int(m.group(1)) if m else None,
                                      "error": node.get("error")}
            for k, v in node.items():
                if isinstance(v, (dict, list)):
                    visit(v, str(k))
        elif isinstance(node, list):
            for item in node:
                visit(item, parent_key)

    visit(obj, None)
    return out


UNSCORED_REASONS = ("verifier_timeout", "sandbox_failure", "output_truncated", "missing_rewards", "agent_exception")
_EXC_TO_REASON = (("timeout", "verifier_timeout"), ("environment", "sandbox_failure"), ("docker", "sandbox_failure"),
                  ("sandbox", "sandbox_failure"), ("verifier", "verifier_timeout"))


def unscored_state(exc_type: str, rewards: Optional[Dict], details: Dict[str, Dict[str, Any]]) -> Tuple[bool, str]:
    """A7 §6.10: a trial is unscored when Harbor recorded an exception, when the rewards are
    missing, or when any criterion's reasoning starts with `unscored:`. A hung test is never a
    miss. -> (unscored, reason) with reason in UNSCORED_REASONS or ""."""
    for d in details.values():
        reasoning = str(d.get("reasoning") or "")
        if reasoning.startswith("unscored:"):
            tag = reasoning.split(":", 1)[1].split()[0] if ":" in reasoning else ""
            return True, tag if tag in UNSCORED_REASONS else "verifier_timeout"
    if exc_type:
        low = exc_type.lower()
        for needle, reason in _EXC_TO_REASON:
            if needle in low:
                return True, reason
        return True, "agent_exception"
    if not isinstance(rewards, dict) or not rewards:
        return True, "missing_rewards"
    return False, ""


def _answer_from_report(trial_dir: Path) -> Optional[Dict]:
    """{"findings": n, "files": [...]} from the trial's downloaded report.json, when Harbor kept it."""
    for rel in ("artifacts/report.json", "artifacts/logs/artifacts/report.json", "verifier/report.json"):
        p = trial_dir / rel
        if p.is_file():
            try:
                rep = json.loads(p.read_text())
            except (OSError, ValueError):
                return None
            finds = rep.get("findings") or [] if isinstance(rep, dict) else []
            return {"findings": len(finds), "files": sorted({str(f.get("file", "")) for f in finds if isinstance(f, dict)})}
    return None


def parse_job(job_dir: Path, *, metadata: Optional[Dict[str, Any]] = None) -> List[Dict]:
    """Harbor `<job>/result.json` (JobResult) -> one record per trial, in Inspect's Score shape (A7):
    {task_id, trial, trial_name, value (= rewards dict), rewards, answer, explanation, metadata,
    unscored, unscored_reason, details, cost_usd, tokens{input,cache,output}, error, elapsed_s,
    agent, agent_version, model}. `details` comes from `<job>/<trial_name>/verifier/reward-details.json`
    when present; `metadata` carries the rc values plus whatever the caller passes (backend, network)."""
    job_dir = Path(job_dir)
    result_file = job_dir / "result.json"
    if not result_file.is_file():
        raise FileNotFoundError(f"no result.json in {job_dir}")
    doc = json.loads(result_file.read_text())
    counter: Counter = Counter()
    out: List[Dict] = []
    for tr in doc.get("trial_results") or []:
        # Harbor names the task after its directory (our task_id); `Task(dir).name` is
        # "security-agents/<task_id>" — strip the org if a result ever carries it.
        task_id = str(tr.get("task_name") or "").rsplit("/", 1)[-1]
        trial_name = str(tr.get("trial_name") or task_id)
        counter[task_id] += 1
        vr = tr.get("verifier_result") or {}
        rewards = vr.get("rewards") if isinstance(vr, dict) else None
        rewards = {str(k): float(v) for k, v in rewards.items()} if isinstance(rewards, dict) else None
        ar = tr.get("agent_result") or {}
        exc = tr.get("exception_info") or None
        exc_type = str(exc.get("exception_type") or "Exception") if exc else ""
        error = f"{exc_type}: {str(exc.get('exception_message') or '')[:200]}" if exc else ""
        started, finished = _parse_dt(tr.get("started_at")), _parse_dt(tr.get("finished_at"))
        elapsed = (finished - started).total_seconds() if started and finished else None
        details: Dict[str, Dict[str, Any]] = {}
        dpath = job_dir / trial_name / "verifier" / "reward-details.json"
        if dpath.is_file():
            try:
                details = parse_reward_details(json.loads(dpath.read_text()))
            except (OSError, ValueError):
                details = {}
        unscored, reason = unscored_state(exc_type, rewards, details)
        info = tr.get("agent_info") or {}
        out.append({
            "task_id": task_id, "trial": counter[task_id], "trial_name": trial_name,
            "value": rewards, "rewards": rewards,
            "answer": _answer_from_report(job_dir / trial_name),
            "explanation": "; ".join(f"{k}: {v['reasoning']}" for k, v in sorted(details.items()) if v.get("reasoning")),
            "metadata": {**(metadata or {}), "rc": {k: v.get("rc") for k, v in sorted(details.items()) if v.get("rc") is not None},
                         "agent_version": info.get("version"), "exception_type": exc_type or None},
            "unscored": unscored, "unscored_reason": reason,
            "details": details,
            "cost_usd": float(ar.get("cost_usd") or 0.0),
            "tokens": {"input": int(ar.get("n_input_tokens") or 0), "cache": int(ar.get("n_cache_tokens") or 0),
                       "output": int(ar.get("n_output_tokens") or 0)},
            "error": error, "elapsed_s": round(elapsed, 3) if elapsed is not None else None,
            "agent": info.get("name"), "agent_version": info.get("version"),
            "model": (info.get("model_info") or {}).get("name"),
        })
    return out


# ----------------------------------------------------------------- outcomes and summary

def trial_outcome(rec: Dict, task: Optional[Task], requires: Sequence[str] = SCORE_NAMES) -> Dict:
    """One trial's scored outcome. Positive: passed iff every score in `requires` is 1.0.
    Negative: passed iff `fp` is 1.0 (no class finding) and every score in `requires` other
    than recall is 1.0. No rewards or a Harbor exception -> error, all scores 0, not passed.
    recall on a negative and fp on a positive are "not-applicable" and reported as None."""
    is_neg = bool(task.is_negative) if task is not None else bool((rec.get("rewards") or {}).get("is_negative", 0))
    rewards = rec.get("rewards")
    if "unscored" in rec:
        unscored, unscored_reason = bool(rec["unscored"]), str(rec.get("unscored_reason") or "")
    else:
        unscored, unscored_reason = unscored_state(str(rec.get("error") or "").split(":")[0], rewards, rec.get("details") or {})
    error = unscored or bool(rec.get("error")) or not isinstance(rewards, dict)
    scores: Dict[str, Optional[float]] = {}
    for s in SCORE_NAMES:
        scores[s] = 0.0 if error else float(rewards.get(s, 0.0))
    if is_neg:
        scores["recall"] = None
        fp_val = None if error else float(rewards.get("fp", 0.0))
        fp = 1 if (error or fp_val is None or fp_val < 1.0) else 0
        need = [s for s in requires if s != "recall"]
        passed = (not error) and fp == 0 and all((scores[s] or 0.0) >= 1.0 for s in need)
    else:
        fp = None
        passed = (not error) and all((scores[s] or 0.0) >= 1.0 for s in requires)
    details = rec.get("details") or {}
    conflict = any("conflict" in str(d.get("reasoning") or "").lower() for d in details.values())
    return {"task_id": rec["task_id"], "trial": rec.get("trial", 1), "is_negative": is_neg, "error": error,
            "unscored": unscored, "unscored_reason": unscored_reason,
            "error_text": rec.get("error") or (f"unscored:{unscored_reason}" if unscored else ""),
            "scores": scores, "fp": fp, "passed": bool(passed), "hidden_patch_conflict": conflict,
            "cost_usd": float(rec.get("cost_usd") or 0.0), "tokens": dict(rec.get("tokens") or {}),
            "reward": None if error else float(rewards.get("reward", 0.0))}


def _ci(k: float, n: int) -> Optional[List[float]]:
    return [round(x, 3) for x in wilson_ci(k, n)] if n else None


def _stderr(outs: List[Dict], value: Callable[[Dict], Optional[float]]) -> Optional[float]:
    """Task-clustered standard error (Miller 2024; Inspect's `stderr(cluster=task)`): trials
    collapse to one mean per task, then SE = sd(task means) / sqrt(tasks). None under 2 tasks."""
    per: Dict[str, List[float]] = defaultdict(list)
    for o in outs:
        v = value(o)
        if v is not None:
            per[o["task_id"]].append(float(v))
    return round(clustered_stderr(per), 4) if len(per) >= 2 else None


def _block(all_outs: List[Dict], trials: int) -> Dict:
    outs = [o for o in all_outs if not o.get("unscored")]          # A7: unscored trials enter no metric
    n_unscored = len(all_outs) - len(outs)
    n = len(outs)
    pos = [o for o in outs if not o["is_negative"]]
    neg = [o for o in outs if o["is_negative"]]
    task_ids = {o["task_id"] for o in outs}
    passed = sum(1 for o in outs if o["passed"])
    b: Dict[str, Any] = {"n": n, "n_unscored": n_unscored,
                         "unscored_reasons": dict(sorted(Counter(o["unscored_reason"] for o in all_outs if o.get("unscored")).items())),
                         "tasks": len(task_ids), "positive_tasks": len({o["task_id"] for o in pos}),
                         "negative_tasks": len({o["task_id"] for o in neg}), "positives": len(pos), "negatives": len(neg),
                         "trials": trials, "passed": passed,
                         "pass_rate": round(passed / n, 3) if n else None, "pass_rate_ci95": _ci(passed, n),
                         "pass_rate_stderr": _stderr(outs, lambda o: 1.0 if o["passed"] else 0.0)}
    k = sum(float(o["scores"]["recall"] or 0.0) for o in pos)
    b["recall"] = round(k / len(pos), 3) if pos else None
    b["recall_ci95"] = _ci(k, len(pos))
    b["recall_stderr"] = _stderr(pos, lambda o: float(o["scores"]["recall"] or 0.0))
    for s in ("fix", "claim_fidelity", "scope_safety"):
        k = sum(float(o["scores"][s] or 0.0) for o in outs)
        b[s] = round(k / n, 3) if n else None
        b[f"{s}_ci95"] = _ci(k, n)
        b[f"{s}_stderr"] = _stderr(outs, lambda o, s=s: float(o["scores"][s] or 0.0))
    fp = sum(int(o["fp"] or 0) for o in neg)
    b["fp"] = fp
    if neg:
        rate, ci = fpr(fp, len(neg))
        b["fpr"], b["fpr_ci95"] = round(rate, 3), [round(x, 3) for x in ci]
    else:
        b["fpr"], b["fpr_ci95"] = None, None
    b["fpr_stderr"] = _stderr(neg, lambda o: float(o["fp"] or 0))
    per_task: Dict[str, List[bool]] = defaultdict(list)
    for o in outs:
        per_task[o["task_id"]].append(bool(o["passed"]))
    full = [v for v in per_task.values() if len(v) == trials]
    b["pass_at_k"] = {str(kk): (round(sum(pass_at_k(trials, sum(v), kk) for v in full) / len(full), 3) if full else None)
                      for kk in range(1, trials + 1)}
    b["pass_pow_k"] = {str(kk): (round(sum(pass_pow_k(sum(v) / trials, kk) for v in full) / len(full), 3) if full else None)
                       for kk in range(1, trials + 1)}
    cost = sum(o["cost_usd"] for o in outs)
    b["cost_usd_total"] = round(cost, 6)
    b["cost_usd_per_task"] = round(cost / len(task_ids), 6) if task_ids else None
    b["tokens"] = {f: sum(int((o["tokens"] or {}).get(f, 0)) for o in outs) for f in ("input", "cache", "output")}
    b["errors"] = sum(1 for o in outs if o["error"])
    b["hidden_patch_conflicts"] = sum(1 for o in outs if o["hidden_patch_conflict"])
    return b


def grouped(outs: List[Dict], key: str, trials: int, order: Optional[Sequence[str]] = None) -> Dict[str, Dict]:
    """Inspect's `grouped(metric, key)`: one block per value of `key` (split, stratum,
    contamination_bin, condition). `order` fixes the key order and keeps empty groups."""
    keys = list(order) if order is not None else sorted({str(o.get(key, "")) for o in outs})
    return {k: _block([o for o in outs if str(o.get(key, "")) == k], trials) for k in keys
            if order is not None or any(str(o.get(key, "")) == k for o in outs)}


def _exclusions(registry: Dict) -> Dict:
    rel = str(registry.get("exclusions") or "")
    path = Path(rel) if Path(rel).is_absolute() else REPO / rel
    by_reason: Counter = Counter()
    n = 0
    if path.is_file():
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            n += 1
            by_reason[str(rec.get("exclusion_reason") or rec.get("reason") or "other")] += 1
    return {"file": rel, "present": path.is_file(), "count": n, "by_reason": dict(sorted(by_reason.items()))}


def build_calib_summary(records: Sequence[Dict], *, tasks: Dict[str, Task], model: Optional[str], condition: str,
                        split: str, cutoffs: Dict[str, str], trials: int, budget_usd: float,
                        prompt_hashes: Dict, registry: Dict, requires: Sequence[str] = SCORE_NAMES,
                        provenance: Optional[Dict] = None) -> Dict:
    """The Layer-6 summary over `parse_job` records. Blocks: overall, per split, per stratum,
    per contamination bin (for `model`); each with recall (positives) / fix / claim_fidelity /
    scope_safety / pass_rate and Wilson CIs, fpr (+ci95) over negatives, pass@k / pass^k,
    cost, errors. Plus exclusions, a power note, the prompt-drift flag and a `tasks` list the
    agent gate reads."""
    outs: List[Dict] = []
    for rec in records:
        task = tasks.get(rec["task_id"])
        o = trial_outcome(rec, task, requires)
        o["split"] = task.split if task else ""
        o["stratum"] = splitmod.stratum(task) if task else "|"
        o["contamination_bin"] = (splitmod.contamination_bin(task.disclosure_date, model or "", cutoffs)
                                  if task else "unknown")
        outs.append(o)
    overall = _block(outs, trials)
    by_split = grouped(outs, "split", trials, order=[s for s in SPLITS if any(o["split"] == s for o in outs)])
    by_stratum = grouped(outs, "stratum", trials)
    by_bin = grouped(outs, "contamination_bin", trials, order=("pre", "post", "unknown"))

    per_task: Dict[str, List[Dict]] = defaultdict(list)
    for o in outs:
        per_task[o["task_id"]].append(o)
    task_rows = []
    for tid in sorted(per_task):
        rows = per_task[tid]
        scored = [r for r in rows if not r["unscored"]]
        t = tasks.get(tid)
        errs = [r["error_text"] for r in rows if r["error"] and not r["unscored"]]
        task_rows.append({"task_id": tid, "eval_id": EVAL_ID, "property": t.property if t else "P4",
                          "split": rows[0]["split"], "stratum": rows[0]["stratum"], "is_negative": rows[0]["is_negative"],
                          "contamination_bin": rows[0]["contamination_bin"], "trials": len(scored),
                          "unscored": len(rows) - len(scored),
                          "passes": sum(1 for r in scored if r["passed"]),
                          "passed": bool(scored) and all(r["passed"] for r in scored),
                          "error": errs[0] if errs else None})

    mode = condition.split("+", 1)[0]
    pinned = {k: str(v) for k, v in ((registry.get("prompt_hashes") or {}).get(mode) or {}).items()}
    is_pinned = all(pinned.get(k) for k in ("system", "user"))
    drift = bool(is_pinned and prompt_hashes and any(pinned.get(k) != prompt_hashes.get(k) for k in ("system", "user")))
    n_pos_tasks = overall["positive_tasks"]
    p0 = overall["recall"] if overall["recall"] is not None else 0.5
    return {
        "eval_id": EVAL_ID, "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
        "model": model, "condition": condition, "requires": list(requires), "split": split, "trials": trials,
        "budget_usd": budget_usd, "cost_usd_total": overall["cost_usd_total"],
        "harbor_version": HARBOR_VERSION, "toolkit_version": toolkit_version(), "git_sha": git_sha(),
        "overall": overall, "evals": {EVAL_ID: overall},
        "splits": by_split, "strata": by_stratum,
        "contamination": {"model": model, "cutoff": str(cutoffs.get(model or "", "unknown")), "bins": by_bin},
        "exclusions": _exclusions(registry),
        "power_note": power_note(n_pos_tasks, p0, POWER_DELTA),
        "prompt_hashes": {"run": dict(prompt_hashes or {}), "registry": pinned, "pinned": is_pinned, "drift": drift},
        "prompt_drift": drift,
        "budget": {"budget_usd": budget_usd, "cost_usd_total": overall["cost_usd_total"],
                   "per_trial_cap_usd": (round(budget_usd / (overall["tasks"] * trials), 6) if overall["tasks"] else None),
                   "note": BUDGET_NOTE},
        "provenance": provenance or {},
        "tasks": task_rows,
        "_reading": {
            "n": "SCORED trials = tasks x trials in the selected split (positives and negatives alike) minus n_unscored; a "
                 "scored trial that failed for a harness reason is counted in `errors` and scored 0",
            "n_unscored": "trials excluded from every metric (A7): Harbor exception, missing rewards, or a criterion reasoning "
                          "starting with `unscored:` (verifier_timeout, sandbox_failure, output_truncated, missing_rewards, "
                          "agent_exception) — a hung test is never a miss; `unscored_reasons` counts them",
            "*_stderr": "task-clustered standard error (Miller 2024 / Inspect `stderr(cluster=task)`): trials collapse to one "
                        "mean per task, SE = sd(task means) / sqrt(tasks); None under 2 tasks. Up to 3x the naive SE when "
                        "trials of one task agree",
            "passed": f"positives: every score in `requires` ({', '.join(requires)}) is 1.0; negatives: fp is 1.0 (no class "
                      "finding on fp_files) and the non-recall scores in `requires` are 1.0; pass_rate = passed / n with a Wilson 95% CI",
            "recall": "over POSITIVE trials only (the verifier's 1.0 'not-applicable' on negatives is ignored); Wilson CI",
            "fix/claim_fidelity/scope_safety": "over all trials (defined for negatives too); Wilson CI",
            "fpr": "false positives / negative trials, where a false positive is a class finding on fp_files; a PROXY, not a "
                   "measured rate over all code; None when the block has no negatives",
            "pass_at_k/pass_pow_k": "over tasks with all `trials` rows; the task is the unit",
            "splits/strata/contamination.bins": "the same block per split, per sub_scenario|library stratum, and per "
                                                "pre|post|unknown bin for `model` (month granularity, evals/calib/cutoffs.yaml)",
            "power_note": "normal-approximation power of n positive tasks to detect a 15-point change from the observed recall",
            "prompt_drift": "true when the registry pins prompt hashes for this condition and this run's differ; `pinned` false "
                            "means the registry has not been filled yet (step 7)",
            "exclusions": "count per categorical reason from the registry's exclusions.jsonl (selection bias is stated in the card)",
            "budget": BUDGET_NOTE,
            "tasks": "task_id -> passed (all trials); the agent gate names any task that passed in the baseline and fails now",
        },
    }


# ----------------------------------------------------------------- report

def _fmt(b: Optional[Dict], s: str) -> str:
    if not b or b.get(s) is None:
        return "—"
    ci = b.get(f"{s}_ci95")
    return fmt_ci(b[s], ci) if ci else f"{b[s]:.2f}"


def _side_by_side(title: str, blocks: Dict[str, Optional[Dict]], trials: int) -> List[str]:
    cols = list(blocks)
    kk = str(trials)
    lines = [f"### {title}", "", "| metric | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
    rows = [("tasks (pos / neg)", lambda b: f"{b['tasks']} ({b['positive_tasks']} / {b['negative_tasks']})" if b and b["n"] else "—"),
            ("n scored trials (unscored)", lambda b: f"{b['n']} ({b['n_unscored']})" if b else "—"),
            ("pass rate", lambda b: _fmt(b, "pass_rate")), ("recall (positives)", lambda b: _fmt(b, "recall")),
            ("fix", lambda b: _fmt(b, "fix")), ("claim fidelity", lambda b: _fmt(b, "claim_fidelity")),
            ("scope safety", lambda b: _fmt(b, "scope_safety")),
            ("FPR (negatives)", lambda b: (_fmt(b, "fpr") + f" ({b['fp']}/{b['negatives']})") if b and b.get("fpr") is not None else "—"),
            (f"pass@{kk}", lambda b: str(b["pass_at_k"].get(kk)) if b and b["n"] else "—"),
            (f"pass^{kk}", lambda b: str(b["pass_pow_k"].get(kk)) if b and b["n"] else "—"),
            ("$/task", lambda b: f"${b['cost_usd_per_task']:.4f}" if b and b.get("cost_usd_per_task") is not None else "—"),
            ("errors", lambda b: str(b["errors"]) if b else "—")]
    for name, f in rows:
        lines.append(f"| {name} | " + " | ".join(f(blocks[c]) for c in cols) + " |")
    lines.append("")
    return lines


def render_calib_report(summary: Dict, records: Sequence[Dict]) -> str:
    o = summary["overall"]
    trials = summary["trials"]
    ph = summary["prompt_hashes"]
    lines = [f"# Calibration run — `{summary['eval_id']}` · {summary['condition']} · split {summary['split']}", "",
             f"Model: `{summary['model']}` · trials: {trials} · tasks: {o['tasks']} ({o['positive_tasks']} positive, "
             f"{o['negative_tasks']} negative) · scored: {o['n']} · unscored: {o['n_unscored']} · passed: {o['passed']} · errors: {o['errors']} · "
             f"cost: ${summary['cost_usd_total']:.4f} of ${summary['budget_usd']:.2f} · harbor {summary['harbor_version']} · "
             f"toolkit {summary['toolkit_version']} @ {summary['git_sha']}", "",
             f"**Pass rate {_fmt(o, 'pass_rate')} · recall {_fmt(o, 'recall')} · FPR {_fmt(o, 'fpr')} · "
             f"pass^{trials} {o['pass_pow_k'].get(str(trials))}**", "",
             f"`passed` requires {', '.join(summary['requires'])} at 1.0 (negatives: fp = 1.0 and the non-recall scores). "
             "CIs are Wilson 95%. recall is over positives only; FPR is a proxy (class findings on fp_files) over negatives.", ""]
    if summary.get("prompt_drift"):
        lines += ["**PROMPT DRIFT**: this run's prompt hashes differ from the registry's pinned hashes "
                  f"(run {ph['run']}, registry {ph['registry']}).", ""]
    elif not ph.get("pinned"):
        lines += ["Prompt hashes are not pinned in the registry yet (step 7); drift cannot be judged.", ""]
    lines += ["## Splits", ""]
    lines += _side_by_side("train / validation / test", {s: summary["splits"].get(s) for s in SPLITS}, trials)
    lines += ["## Contamination", "",
              f"Model `{summary['contamination']['model']}` cutoff month: {summary['contamination']['cutoff']} "
              "(a disclosure on or before the last day of that month is `pre`).", ""]
    lines += _side_by_side("pre / post / unknown", summary["contamination"]["bins"], trials)
    lines += ["## Strata (sub_scenario|library)", ""]
    if summary["strata"]:
        lines += _side_by_side("per stratum", summary["strata"], trials)
    else:
        lines += ["No trials.", ""]
    lines += ["## Power", "", summary["power_note"], ""]
    ex = summary["exclusions"]
    lines += ["## Exclusions", ""]
    if ex["present"]:
        lines += [f"{ex['count']} candidate(s) excluded (`{ex['file']}`):", ""]
        lines += [f"- {r}: {n}" for r, n in ex["by_reason"].items()] or ["- none"]
    else:
        lines += [f"`{ex['file']}` not present on this checkout."]
    lines += ["", "## Trials", "",
              "| task | trial | split | bin | neg | recall | fix | claim | scope | fp | passed | cost | error |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    tasks_by_id = {t["task_id"]: t for t in summary["tasks"]}
    for rec in records:
        t = tasks_by_id.get(rec["task_id"], {})
        o2 = trial_outcome(rec, None, summary["requires"])
        o2["is_negative"] = t.get("is_negative", o2["is_negative"])
        s = o2["scores"]
        fmt = lambda v: "—" if v is None else f"{v:g}"  # noqa: E731
        lines.append(f"| {rec['task_id']} | {rec.get('trial')} | {t.get('split', '')} | {t.get('contamination_bin', '')} | "
                     f"{'yes' if o2['is_negative'] else ''} | {fmt(s['recall'])} | {fmt(s['fix'])} | {fmt(s['claim_fidelity'])} | "
                     f"{fmt(s['scope_safety'])} | {fmt(o2['fp'])} | {'pass' if o2['passed'] else 'FAIL'} | "
                     f"${o2['cost_usd']:.4f} | {o2['error_text'] or '-'} |")
    p = summary.get("provenance") or {}
    lines += ["", "## Provenance", ""]
    for k, v in p.items():
        lines.append(f"- {k}: {v}")
    lines += [f"- budget: ${summary['budget_usd']:.2f} cap, ${summary['cost_usd_total']:.4f} spent — {BUDGET_NOTE}"]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- calib-run

def _load_tasks(path: Path) -> List[Task]:
    return splitmod.load_tasks_jsonl(path) if Path(path).is_file() else []


def _rel(p: Path) -> str:
    p = Path(p).resolve()
    return str(p.relative_to(REPO)) if p.is_relative_to(REPO) else str(p)


def run_calib(*, split: str, model: Optional[str], trials: int, budget_usd: float, condition: str, concurrency: int,
              ablation: Optional[str], anchor: bool, unseal_test: bool, out_dir: Path, dry_run: bool = False,
              harbor_bin: str = "harbor", env: str = "docker", baseline: str = "ours", allow_disabled: bool = False,
              registry_path: Path = REGISTRY_FILE, baselines_path: Path = BASELINES_FILE, tasks_path: Path = TASKS_JSONL,
              splits_dir: Path = SPLITS_DIR, log: Optional[Callable] = print,
              runner: Callable = subprocess.run) -> Dict:
    """Refuse, plan, (dry-run: print and stop), run harbor, parse, summarise. See the module docstring."""
    if split not in SPLITS:
        raise CalibError(f"--split must be one of {SPLITS}, got {split!r}")
    if env not in ENVS:
        raise CalibError(f"--env must be one of {ENVS}, got {env!r}")
    if budget_usd is None or not float(budget_usd) > 0:
        raise CalibError("--budget-usd is required and must be > 0 (every run names what it may spend)")
    if trials < 1:
        raise CalibError("--trials must be >= 1")
    if split == "test" and not unseal_test:
        raise SealedTestError("--split test is sealed: pass --unseal-test to touch it (a deliberate, logged act; "
                              "the plan allows it once)")
    cond_name = condition_name(condition, ablation)
    requires = condition_requires(ablation)
    base = baseline_by_name(baseline, load_baselines(baselines_path), allow_disabled=allow_disabled)
    model = model or base.get("model") or None
    if not model and base["kind"] not in MODEL_FREE_KINDS:
        raise CalibError("--model is required (no default: every run names the model it spends on)")
    registry = load_calib_registry(registry_path)
    tasks = _load_tasks(tasks_path)
    selected = [t for t in tasks if t.split == split]
    extra: List[str] = ["-e", env]
    if anchor:
        ids = [str(x) for x in (registry.get("anchor") or [])]
        if not ids:
            raise CalibError("--anchor: the registry's anchor list is empty (filled at step 7)")
        selected = [t for t in selected if t.task_id in ids] or [t for t in tasks if t.task_id in ids]
        for tid in ids:
            extra += ["-i", tid]
    n_planned = max(1, len(selected)) * trials
    per_trial_cap = round(float(budget_usd) / n_planned, 6)
    agent_kwargs = dict(base["agent_kwargs"])
    if base["kind"] == "ours":
        agent_kwargs["condition"] = cond_name
        agent_kwargs["budget_usd"] = f"{per_trial_cap:.6f}"
    if base["version"]:
        agent_kwargs["version"] = base["version"]
    run_id = make_run_id()
    run_dir = Path(out_dir) / run_id
    jobs_dir = run_dir / "jobs"
    job_name = f"calib-{CLASS_NAME}-{split}-{cond_name}-{base['name']}"
    argv = harbor_argv(dataset_dir=Path(splits_dir) / split, agent=base["harbor_agent"], model=model, trials=trials,
                       concurrency=concurrency, jobs_dir=jobs_dir, job_name=job_name, agent_kwargs=agent_kwargs, extra=extra)
    argv[0] = harbor_bin
    provenance = {"backend": env, "baseline": base["name"], "baseline_kind": base["kind"], "harbor_agent": base["harbor_agent"],
                  "agent_version_pin": base["version"], "network": base.get("network"),
                  "condition_asymmetry": ("installed baseline: model key inside the box, allowlist egress to the model API"
                                          if base.get("network") == "allowlist" else
                                          "external agent / tool: the box has no network; the model loop runs on the host"),
                  "harbor_version": HARBOR_VERSION, "toolkit_version": toolkit_version(), "toolkit_sha": git_sha()}
    plan = {"run_id": run_id, "argv": argv, "split": split, "condition": cond_name, "requires": list(requires),
            "model": model, "trials": trials, "budget_usd": float(budget_usd), "per_trial_cap_usd": per_trial_cap,
            "tasks_selected": [t.task_id for t in selected], "anchor": anchor, "baseline": base["name"], "env": env,
            "unseal_test": unseal_test, "dry_run": dry_run, "provenance": provenance}
    if log:
        log(f"plan: {len(selected)} task(s) x {trials} trial(s) in split {split}, condition {cond_name}, baseline {base['name']} "
            f"({base['kind']}), model {model}, per-trial cap ${per_trial_cap:.4f}, run cap ${float(budget_usd):.2f}, backend {env}")
        if split == "test":
            log("WARNING: touching the sealed test split (--unseal-test); this is the one reported primary number")
        log("argv: " + shlex.join(argv))
    if dry_run:
        if log:
            log("dry run: nothing written, nothing started")
        return plan

    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "plan.json").write_text(json.dumps(plan, indent=1, default=str))
    proc = runner(argv, cwd=str(REPO), check=False)
    rc = getattr(proc, "returncode", 0)
    job_dir = jobs_dir / job_name
    meta = {"backend": env, "network": base.get("network"), "baseline": base["name"]}
    records = parse_job(job_dir, metadata=meta) if (job_dir / "result.json").is_file() else []
    if log and not records:
        log(f"warning: harbor exited {rc} and left no result.json in {job_dir}")
    cutoffs = splitmod.load_cutoffs()
    summary = build_calib_summary(records, tasks={t.task_id: t for t in tasks}, model=model, condition=cond_name,
                                  split=split, cutoffs=cutoffs, trials=trials, budget_usd=float(budget_usd),
                                  prompt_hashes=_prompt_hashes_for(cond_name, selected), registry=registry,
                                  requires=requires, provenance={**provenance, "harbor_rc": rc})
    summary["run_id"] = run_id
    with (run_dir / "samples.jsonl").open("w") as fh:
        for rec in records:
            o = trial_outcome(rec, {t.task_id: t for t in tasks}.get(rec["task_id"]), requires)
            fh.write(json.dumps({**rec, **{k: o[k] for k in ("passed", "scores", "fp", "is_negative", "hidden_patch_conflict")},
                                 "condition": cond_name, "split": split}, sort_keys=True, default=str) + "\n")
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1, default=str))
    (run_dir / "report.md").write_text(render_calib_report(summary, records))
    (Path(out_dir) / "latest-calib.json").write_text(json.dumps(
        {"run_id": run_id, "path": _rel(run_dir), "generated": summary["generated"], "model": model,
         "condition": cond_name, "split": split}, indent=1))
    if log:
        log(f"wrote {run_dir}")
    summary["run_dir"] = str(run_dir)
    return summary


# ----------------------------------------------------------------- calib-validate

def _crit(rec: Dict, name: str) -> Tuple[Optional[float], Optional[int]]:
    d = (rec.get("details") or {}).get(name) or {}
    return (d.get("score"), d.get("rc")) if d else (None, None)


def validity_from_records(nop: Sequence[Dict], oracle: Sequence[Dict], tasks: Sequence[Task]) -> List[ValidityResult]:
    """The rc rules of CONTRACTS.md on the two gate jobs. nop run (positives): `hidden_test_passes`
    score 0 with rc == 1 (tests failed, not a collection error) and `suite_passes` 1; oracle run:
    both 1; negatives: `suite_passes` 1 in both runs. Reasons are categorical."""
    nop_by = {r["task_id"]: r for r in nop}
    ora_by = {r["task_id"]: r for r in oracle}
    out = []
    for t in tasks:
        n, o = nop_by.get(t.task_id), ora_by.get(t.task_id)
        details: Dict[str, Any] = {}
        reasons: List[str] = []
        if n is None:
            reasons.append("no_nop_result")
        if o is None:
            reasons.append("no_oracle_result")
        noop_fix = ref_fix = None
        if n is not None:
            if n.get("error"):
                reasons.append("nop_run_error")
            hs, hrc = _crit(n, "hidden_test_passes")
            ss, src = _crit(n, "suite_passes")
            details.update({"noop_rc": hrc, "noop_suite_rc": src})
            noop_fix = hs
            if not t.is_negative:
                if hs is None:
                    reasons.append("noop_fix_unscored")
                elif hs >= 1.0:
                    reasons.append("noop_passes")
                elif hrc is not None and hrc != 1:
                    reasons.append("noop_collection_error")
            if ss is None or ss < 1.0:
                reasons.append("suite_fails_at_vuln")
        if o is not None:
            if o.get("error"):
                reasons.append("oracle_run_error")
            hs, hrc = _crit(o, "hidden_test_passes")
            ss, src = _crit(o, "suite_passes")
            details.update({"reference_rc": hrc, "reference_suite_rc": src})
            ref_fix = hs
            if not t.is_negative and (hs is None or hs < 1.0):
                reasons.append("reference_fails")
            if ss is None or ss < 1.0:
                reasons.append("suite_fails_after_reference")
        out.append(ValidityResult(task_id=t.task_id, eval_id=t.eval_id, valid=not reasons, noop_fix=noop_fix,
                                  reference_fix=ref_fix, reason=",".join(dict.fromkeys(reasons)), mode="harbor",
                                  details=details))
    return out


def run_validate(*, out_dir: Path = RESULTS, mode: str = "container", dry_run: bool = False, env: str = "docker",
                 harbor_bin: str = "harbor", concurrency: int = 4, tasks_dir: Path = TASKS_DIR,
                 tasks_path: Path = TASKS_JSONL, log: Optional[Callable] = print, runner: Callable = subprocess.run) -> Dict:
    """The validity gate as two Harbor jobs over tasks/: `-a nop` and `-a oracle`, then the rc
    rules of `validity_from_records`. `mode` is recorded; only Harbor ("container") exists."""
    if mode != "container":
        raise CalibError(f"calib-validate runs through Harbor only (mode container), got {mode!r}")
    if env not in ENVS:
        raise CalibError(f"--env must be one of {ENVS}, got {env!r}")
    run_id = make_run_id()
    run_dir = Path(out_dir) / run_id
    jobs_dir = run_dir / "jobs"
    argvs = {}
    for leg in ("nop", "oracle"):
        a = harbor_argv(dataset_dir=Path(tasks_dir), agent=leg, model=None, trials=1, concurrency=concurrency,
                        jobs_dir=jobs_dir, job_name=f"calib-{CLASS_NAME}-validate-{leg}", agent_kwargs={}, extra=["-e", env])
        a[0] = harbor_bin
        argvs[leg] = a
        if log:
            log(f"argv[{leg}]: " + shlex.join(a))
    if dry_run:
        if log:
            log("dry run: nothing written, nothing started")
        return {"run_id": run_id, "argv": argvs, "dry_run": True}
    run_dir.mkdir(parents=True, exist_ok=True)
    recs: Dict[str, List[Dict]] = {}
    for leg, a in argvs.items():
        runner(a, cwd=str(REPO), check=False)
        jd = jobs_dir / f"calib-{CLASS_NAME}-validate-{leg}"
        recs[leg] = parse_job(jd) if (jd / "result.json").is_file() else []
    tasks = _load_tasks(tasks_path)
    results = validity_from_records(recs["nop"], recs["oracle"], tasks)
    doc = {"run_id": run_id, "generated": dt.datetime.now(dt.timezone.utc).isoformat(), "mode": "harbor", "backend": env,
           "results": [r.to_record() for r in results], "valid": [r.task_id for r in results if r.valid],
           "quarantined": [{"task_id": r.task_id, "eval_id": r.eval_id, "reason": r.reason} for r in results if not r.valid]}
    (run_dir / "validity.json").write_text(json.dumps(doc, indent=1, default=str))
    lines = [f"# Calibration validity gate · run `{run_id}`", "",
             f"tasks: {len(results)} · valid: {len(doc['valid'])} · quarantined: {len(doc['quarantined'])}", "",
             "| task | valid | noop hidden | noop rc | noop suite rc | reference hidden | reference rc | reason |",
             "|---|---|---|---|---|---|---|---|"]
    for r in results:
        d = r.details
        lines.append(f"| {r.task_id} | {'yes' if r.valid else 'NO'} | {r.noop_fix} | {d.get('noop_rc')} | {d.get('noop_suite_rc')} | "
                     f"{r.reference_fix} | {d.get('reference_rc')} | {r.reason or '-'} |")
    (run_dir / "report.md").write_text("\n".join(lines) + "\n")
    (Path(out_dir) / "latest-calib-validate.json").write_text(json.dumps({"run_id": run_id, "path": _rel(run_dir)}, indent=1))
    if log:
        log(f"valid {len(doc['valid'])} · quarantined {len(doc['quarantined'])} · wrote {run_dir}")
    return {"run_id": run_id, "run_dir": str(run_dir), "valid": doc["valid"], "quarantined": doc["quarantined"]}


# ----------------------------------------------------------------- calib-split

def _write_registry(path: Path, entry: Dict) -> None:
    """Rewrite the registry entry, keeping the file's leading comment header."""
    header = []
    if Path(path).is_file():
        for line in Path(path).read_text().splitlines():
            if line.startswith("#"):
                header.append(line)
            else:
                break
    body = {k: v for k, v in entry.items() if not k.startswith("_")}
    Path(path).write_text("\n".join(header) + ("\n" if header else "") +
                          yaml.safe_dump(body, sort_keys=False, width=100, allow_unicode=True))


def _write_tasks_jsonl(tasks: Sequence[Task], path: Path) -> None:
    Path(path).write_text("".join(json.dumps(t.to_record(), sort_keys=True) + "\n" for t in tasks))


def run_split(*, seed: Optional[int], check: bool, unseal_test: bool, registry_path: Path = REGISTRY_FILE,
              tasks_path: Path = TASKS_JSONL, class_dir: Path = CALIB_DIR / CLASS_NAME, log: Optional[Callable] = print) -> int:
    registry = load_calib_registry(registry_path)
    tasks_dir = Path(class_dir) / "tasks"
    splits_dir = Path(class_dir) / "splits"
    if not Path(tasks_path).is_file():
        if log:
            log(f"no tasks at {tasks_path} (run calib-build first)")
        return 2
    tasks = splitmod.load_tasks_jsonl(tasks_path)
    if check:
        ok, msg = splitmod.check_seal(registry, tasks_dir)
        if log:
            log(msg)
        return 0 if ok else 1
    seed = int(registry["splits"]["seed"]) if seed is None else int(seed)
    fractions = tuple(float(x) for x in registry["splits"]["fractions"])
    assignment = splitmod.assign(tasks, seed=seed, fractions=fractions)  # type: ignore[arg-type]
    for w in splitmod.check_balance(tasks):
        if log:
            log(f"WARNING: {w}")
    cutoffs = splitmod.load_cutoffs(REPO / str(registry["cutoffs"]))
    new_tasks = []
    for t in tasks:
        rec = t.to_record()
        rec["split"] = assignment[t.task_id]
        rec["contamination"] = {m: splitmod.contamination_bin(t.disclosure_date, m, cutoffs) for m in sorted(cutoffs)}
        new_tasks.append(Task(**rec))
    splitmod.write_splits(new_tasks, assignment, splits_dir=splits_dir, class_dir=Path(class_dir), seed=seed)
    test_pairs = [(t.task_id, splitmod.dir_hash(tasks_dir / t.task_id)) for t in new_tasks if assignment[t.task_id] == "test"]
    new_hash = splitmod.seal_hash(test_pairs)
    old_hash = str(registry["splits"].get("test_hash") or "")
    if old_hash and old_hash != new_hash and not unseal_test:
        if log:
            log(f"REFUSED: the test split is sealed ({old_hash[:12]}…) and this assignment would change it "
                f"({new_hash[:12]}…); pass --unseal-test to reseal deliberately. Nothing written.")
        return 1
    _write_tasks_jsonl(new_tasks, tasks_path)
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    registry["splits"].update({"seed": seed, "counts": splitmod.counts(new_tasks, assignment), "test_hash": new_hash,
                               "sealed_at": today if (not old_hash or old_hash != new_hash) else registry["splits"]["sealed_at"],
                               "manifests": {s: _rel(splitmod.manifest_path(s, splits_dir)) for s in SPLITS}})
    _write_registry(registry_path, registry)
    if log:
        c = registry["splits"]["counts"]
        log(f"assigned {len(new_tasks)} tasks (seed {seed}): train {c['train']} · validation {c['validation']} · "
            f"test {c['test']} · negatives {c['negatives']}; test_hash {new_hash[:12]}…; wrote {splits_dir} and {_rel(registry_path)}")
    return 0


# ----------------------------------------------------------------- calib-compare

def _run_records(ref: str, results_dir: Path = RESULTS) -> Tuple[Path, List[Dict]]:
    p = Path(ref)
    if not p.is_dir():
        p = Path(results_dir) / ref
    samples = p / "samples.jsonl"
    if not samples.is_file():
        raise CalibError(f"{ref}: no samples.jsonl under {p}")
    return p, [json.loads(line) for line in samples.read_text().splitlines() if line.strip()]


def run_compare(a: str, b: str, *, results_dir: Path = RESULTS, log: Optional[Callable] = print) -> Dict:
    pa, ra = _run_records(a, results_dir)
    pb, rb = _run_records(b, results_dir)
    res = compare(per_task_pass(ra, key="passed"), per_task_pass(rb, key="passed"))
    res["a"], res["b"] = _rel(pa), _rel(pb)
    if log:
        if res["n"] == 0:
            log("no tasks in common")
        else:
            bs, mc = res["bootstrap"], res["mcnemar"]
            log(f"{res['n']} shared tasks · pass@1 A {res['mean_a']:.3f} -> B {res['mean_b']:.3f} · delta {bs['delta']:+.3f} "
                f"[{bs['ci95'][0]:+.3f}, {bs['ci95'][1]:+.3f}] (paired bootstrap, P(delta<=0) {bs['p_delta_le_0']:.3f}) · "
                f"McNemar b={mc['b']} c={mc['c']} p={mc['p']:.4f}")
        log(json.dumps(res, indent=1))
    return res


# ----------------------------------------------------------------- CLI

def _ingest_main(argv: List[str]) -> int:
    try:
        from .ingest import main as ingest_main   # W-A
    except ImportError:
        print("calib-ingest: evals.calib.ingest is not on this checkout (W-A's branch); nothing to run", file=sys.stderr)
        return 2
    return int(ingest_main(argv) or 0)


#: Base-image minors whose `python:<minor>-slim` tag `--resolve-digests` pins (A5/A7: pin digests, not tags).
BASE_MINORS = ("3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15", "3.16")


def digest_argv(tag: str) -> List[str]:
    """Pure: the `docker manifest inspect` argv that yields a tag's sha256 digest."""
    return ["docker", "manifest", "inspect", "--verbose", str(tag)]


def docker_available(which: Callable = None, runner: Callable = subprocess.run) -> bool:
    """True when a docker CLI exists AND the daemon answers `docker info`. Never starts anything."""
    import shutil
    exe = (which or shutil.which)("docker")
    if not exe:
        return False
    try:
        proc = runner([exe, "info"], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return getattr(proc, "returncode", 1) == 0


def resolve_digests(*, dry_run: bool, minors: Sequence[str] = BASE_MINORS, log: Optional[Callable] = print,
                    available: Callable[[], bool] = docker_available) -> int:
    """`calib-build --resolve-digests`: resolve `python:<minor>-slim` tags to sha256 digests with
    `docker manifest inspect` and hand them to W-B's `build.write_base_digests` (repos.yaml
    `base_digests`). Refuses cleanly when docker is not running — it never starts docker."""
    tags = [f"python:{m}-slim" for m in minors]
    argvs = [digest_argv(t) for t in tags]
    if dry_run:
        if log:
            for a in argvs:
                log("argv: " + shlex.join(a))
            log("dry run: nothing resolved, nothing written")
        return 0
    if not available():
        raise CalibError("--resolve-digests needs a running docker daemon (colima is stopped on this Mac and nothing "
                         "here starts it); run it once docker is up, or in CI")
    try:
        from .build import write_base_digests   # W-B hook: (Dict[tag, digest]) -> Path
    except ImportError:
        raise CalibError("evals.calib.build.write_base_digests is not on this checkout (W-B's branch)")
    digests: Dict[str, str] = {}
    for tag, a in zip(tags, argvs):
        proc = subprocess.run(a, capture_output=True, text=True, timeout=120, check=False)
        m = re.search(r'"digest"\s*:\s*"(sha256:[0-9a-f]{64})"', proc.stdout or "")
        if proc.returncode == 0 and m:
            digests[tag] = m.group(1)
        elif log:
            log(f"warning: no digest for {tag} (rc {proc.returncode})")
    path = write_base_digests(digests)
    if log:
        log(f"wrote {len(digests)} digest(s) to {path}")
    return 0


def _build_main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals calib-build")
    ap.add_argument("--dry-run", action="store_true", help="print the selection funnel; build nothing")
    ap.add_argument("--candidates", default=str(CANDIDATES_FILE), help="candidates.jsonl (default: the class's)")
    ap.add_argument("--all", action="store_true", help="build every record, not only status == selected")
    ap.add_argument("--work", default=str(REPO / ".cache" / "calib"), help="clone/work directory")
    ap.add_argument("--with-sast", action="store_true", dest="with_sast",
                    help="bake the SAST tools of enabled/disabled sast baselines into the images (A4)")
    ap.add_argument("--resolve-digests", action="store_true", dest="resolve_digests",
                    help="resolve python:<minor>-slim tags to sha256 digests (needs a RUNNING docker; never starts it)")
    args = ap.parse_args(argv)
    if args.resolve_digests:
        return resolve_digests(dry_run=args.dry_run)
    try:
        from .build import build_all   # W-B
    except ImportError:
        print("calib-build: evals.calib.build is not on this checkout (W-B's branch); nothing to run", file=sys.stderr)
        return 2
    cpath = Path(args.candidates)
    if not cpath.is_file():
        print(f"calib-build: {cpath} does not exist (run calib-ingest first)", file=sys.stderr)
        return 2
    try:
        from .ingest import read_candidates   # W-A: skips the first-line {"_meta": ...} provenance record
        cands = [dict(c) for c in read_candidates(cpath)]
    except ImportError:
        cands = [c for c in (json.loads(l) for l in cpath.read_text().splitlines() if l.strip()) if "_meta" not in c]
    if not args.all:
        cands = [c for c in cands if c.get("status") == "selected"]
    kwargs: Dict[str, Any] = {"work": Path(args.work), "dry_run": args.dry_run, "log": print}
    if args.with_sast:
        tools = sorted({t for b in load_baselines() if b["kind"] == "sast" for t in (b.get("needs_image_tools") or [])})
        kwargs["sast_tools"] = tools
    funnel = build_all(cands, **kwargs)
    print(json.dumps(funnel, indent=1, default=str))
    return 0


def _validate_main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals calib-validate",
                                 description="The validity gate as two Harbor jobs (nop, oracle) over tasks/.")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--mode", default="container", choices=("container",))
    ap.add_argument("--env", default="docker", choices=ENVS)
    ap.add_argument("--out", default=str(RESULTS), metavar="DIR")
    ap.add_argument("--harbor-bin", default="harbor", dest="harbor_bin")
    ap.add_argument("-n", "--concurrency", type=int, default=4)
    args = ap.parse_args(argv)
    run_validate(out_dir=Path(args.out), mode=args.mode, dry_run=args.dry_run, env=args.env, harbor_bin=args.harbor_bin,
                 concurrency=args.concurrency)
    return 0


def _split_main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals calib-split")
    ap.add_argument("--seed", type=int, default=None, help="default: the registry's splits.seed")
    ap.add_argument("--check", action="store_true", help="recompute test_hash and compare; write nothing")
    ap.add_argument("--unseal-test", action="store_true", dest="unseal_test", help="allow the seal to change")
    args = ap.parse_args(argv)
    return run_split(seed=args.seed, check=args.check, unseal_test=args.unseal_test)


def _run_main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals calib-run",
                                 description="Run one condition over one split through `harbor run` and summarise.")
    ap.add_argument("--model", default=None, help="model id (required unless the baseline is a control or a SAST tool)")
    ap.add_argument("--trials", type=int, default=1)
    ap.add_argument("--budget-usd", type=float, default=None, dest="budget_usd", help="run cap in USD (required, > 0)")
    ap.add_argument("--condition", default=CLASS_BLIND, choices=MODES)
    ap.add_argument("--split", default="train", choices=SPLITS)
    ap.add_argument("--ablation", default=None, choices=ABLATIONS)
    ap.add_argument("--anchor", action="store_true", help="only the registry's anchor tasks (monthly drift check)")
    ap.add_argument("--unseal-test", action="store_true", dest="unseal_test")
    ap.add_argument("--baseline", default="ours", help="entry of evals/calib/baselines.yaml")
    ap.add_argument("--allow-disabled", action="store_true", dest="allow_disabled")
    ap.add_argument("--env", default="docker", choices=ENVS, help="Harbor environment backend (-e)")
    ap.add_argument("-n", "--concurrency", type=int, default=4)
    ap.add_argument("--out", default=str(RESULTS), metavar="DIR")
    ap.add_argument("--harbor-bin", default="harbor", dest="harbor_bin")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    run_calib(split=args.split, model=args.model, trials=args.trials, budget_usd=args.budget_usd, condition=args.condition,
              concurrency=args.concurrency, ablation=args.ablation, anchor=args.anchor, unseal_test=args.unseal_test,
              out_dir=Path(args.out), dry_run=args.dry_run, harbor_bin=args.harbor_bin, env=args.env,
              baseline=args.baseline, allow_disabled=args.allow_disabled)
    return 0


def _compare_main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals calib-compare")
    ap.add_argument("a", help="run id under evals/results or a run dir")
    ap.add_argument("b")
    ap.add_argument("--results", default=str(RESULTS), metavar="DIR")
    args = ap.parse_args(argv)
    run_compare(args.a, args.b, results_dir=Path(args.results))
    return 0


COMMANDS = {"calib-ingest": _ingest_main, "calib-build": _build_main, "calib-validate": _validate_main,
            "calib-split": _split_main, "calib-run": _run_main, "calib-compare": _compare_main}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in COMMANDS:
        print(f"usage: python -m evals {{{' | '.join(COMMANDS)}}} ...", file=sys.stderr)
        return 2
    try:
        return COMMANDS[argv[0]](argv[1:])
    except CalibError as e:
        print(f"{argv[0]}: refused: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
