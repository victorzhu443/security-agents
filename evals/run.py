"""Run the evals: grade vuln/ and clean/ of every task, K trials each, and write one
run directory in the labs' layout (EVALS-PLAN.md Layer 6).

    python -m evals run                                   # every eval, 1 trial
    python -m evals run --strict                          # exit 1 on any failed/errored task
    python -m evals run --eval egress --eval P9           # by name, id, or property
    python -m evals run --trials 3 --only P1-option-node-shape-01
    python -m evals run --out /tmp/results                # run dirs go under this dir

Output, per run:

    <out>/<run_id>/samples.jsonl   one record per task x trial x variant
    <out>/<run_id>/summary.json    per eval and overall: n, recall, precision (Wilson 95%
                                   CI), errors, historical_misses; pass@k / pass^k when
                                   trials > 1; toolkit_version, git_sha, python, platform
    <out>/<run_id>/report.md       the same as tables
    <out>/latest.json              {"run_id": ...} -> the run above

`run_id` = `<UTC yyyymmddThhmmssZ>-<git sha7>`. Run directories are gitignored; a
release publishes one run's summary.json as `evals/baselines/<label>.json`
(`python -m evals baseline publish`) and `python -m evals gate` compares every later run
against it (evals/gate.py).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .graders import Case, Result, default_graders
from .metrics import fmt_ci, pass_at_k, pass_pow_k, wilson_ci
from .registry import load_registry, select

REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "evals" / "results"


def toolkit_version() -> str:
    """The version in this checkout's pyproject (install metadata can be stale)."""
    m = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
    return m.group(1) if m else "unknown"


def git_sha(short: int = 7) -> str:
    git = shutil.which("git")
    if not git:
        return "nogit"
    try:
        out = subprocess.run([git, "rev-parse", f"--short={short}", "HEAD"], cwd=REPO,
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return "nogit"
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else "nogit"


def make_run_id(now: Optional[dt.datetime] = None) -> str:
    now = now or dt.datetime.now(dt.timezone.utc)
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{git_sha()}"


# ----------------------------------------------------------------- discovery

def discover(cases_dir: Path) -> List[Case]:
    cases: List[Case] = []
    for y in sorted(cases_dir.glob("*/*/case.yaml")):
        data = yaml.safe_load(y.read_text()) or {}
        missing = [k for k in ("id", "property", "grader", "expect") if k not in data]
        if missing:
            raise ValueError(f"{y}: missing {missing}")
        for v in ("vuln", "clean"):
            if not (y.parent / v).is_dir():
                raise ValueError(f"{y.parent}: missing {v}/ directory")
        cases.append(Case(id=data["id"], property=data["property"],
                          origin=data.get("origin", "derived"), grader=data["grader"],
                          expect=data["expect"], path=y.parent,
                          description=data.get("description", ""),
                          canary=str(data.get("canary", "") or "")))
    return cases


# ----------------------------------------------------------------- grading

def _variant(res: Result, elapsed: float) -> Dict:
    return {"detected": res.detected, "metrics": res.metrics, "evidence": res.evidence,
            "error": res.error, "elapsed_s": round(elapsed, 4)}


def grade_case(case: Case, graders) -> Dict:
    """Grade both variants once. A task passes when vuln/ is detected and clean/ is not."""
    g = graders.get(case.grader)
    if g is None:
        return {"id": case.id, "property": case.property, "origin": case.origin,
                "grader": case.grader, "description": case.description,
                "error": f"unknown grader {case.grader!r}", "passed": False,
                "recall_hit": False, "precision_hit": False}
    t0 = time.perf_counter()
    rv: Result = g.grade(case, "vuln")
    t1 = time.perf_counter()
    rc: Result = g.grade(case, "clean")
    t2 = time.perf_counter()
    error = rv.error or rc.error
    passed = (error is None) and rv.detected and not rc.detected
    return {
        "id": case.id, "property": case.property, "origin": case.origin, "grader": case.grader,
        "description": case.description,
        "vuln": _variant(rv, t1 - t0),
        "clean": _variant(rc, t2 - t1),
        "error": error, "passed": passed,
        # recall counts a task once if vuln was detected; precision if clean was not
        "recall_hit": bool(rv.detected and not rv.error),
        "precision_hit": bool((not rc.detected) and not rc.error),
    }


def samples_from_row(row: Dict) -> List[Dict]:
    """The per-sample records (task x trial x variant) of one graded row."""
    out = []
    for variant in ("vuln", "clean"):
        v = row.get(variant) or {}
        out.append({
            "eval_id": row.get("eval_id"), "task_id": row["id"], "trial": row.get("trial", 1),
            "variant": variant, "property": row["property"], "grader": row["grader"],
            "origin": row["origin"],
            "detected": v.get("detected"), "metrics": v.get("metrics", {}),
            "evidence": v.get("evidence", ""),
            "error": v.get("error") if v else row.get("error"),
            "elapsed_s": v.get("elapsed_s"),
        })
    return out


# ----------------------------------------------------------------- summary

def _block(rows: List[Dict]) -> Dict:
    n = len(rows)
    rh = sum(bool(r.get("recall_hit")) for r in rows)
    ph = sum(bool(r.get("precision_hit")) for r in rows)
    tasks = {r.get("id", i) for i, r in enumerate(rows)}
    hist = {r.get("id", i) for i, r in enumerate(rows) if r.get("origin") == "historical-miss"}
    b = {
        "n": n, "tasks": len(tasks), "cases": n,          # `cases` kept for older readers
        "recall_hits": rh, "precision_hits": ph,
        "recall": round(rh / n, 3) if n else None,
        "recall_ci95": [round(x, 3) for x in wilson_ci(rh, n)] if n else None,
        "precision": round(ph / n, 3) if n else None,
        "precision_ci95": [round(x, 3) for x in wilson_ci(ph, n)] if n else None,
        "passed": sum(bool(r.get("passed")) for r in rows),
        "errors": sum(bool(r.get("error")) for r in rows),
        "historical_misses": len(hist),
    }
    trials = max((int(r.get("trial", 1)) for r in rows), default=1)
    if trials > 1:
        per_task: Dict = defaultdict(list)
        for r in rows:
            per_task[r.get("id")].append(bool(r.get("passed")))
        full = [v for v in per_task.values() if len(v) == trials]
        b["trials"] = trials
        if full:
            b["pass_at_k"] = {str(k): round(sum(pass_at_k(trials, sum(v), k) for v in full) / len(full), 3)
                              for k in range(1, trials + 1)}
            b["pass_pow_k"] = {str(k): round(sum(pass_pow_k(sum(v) / trials, k) for v in full) / len(full), 3)
                               for k in range(1, trials + 1)}
    return b


def summarize(rows: List[Dict], by: str = "property") -> Dict:
    """Per-group blocks keyed by `by` (property or eval_id) plus `_overall`."""
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        groups[r.get(by) or "?"].append(r)
    out = {k: _block(v) for k, v in sorted(groups.items())}
    out["_overall"] = _block(rows)
    return out


def build_summary(rows: List[Dict], registry: Dict[str, Dict], *, run_id: str, trials: int,
                  selected: List[str], cases_dir: Path) -> Dict:
    per_eval = summarize(rows, by="eval_id")
    overall = per_eval.pop("_overall")
    evals = {}
    for eid in selected:
        e = registry[eid]
        block = per_eval.get(eid, _block([]))
        evals[eid] = {"property": e["property"], "name": e["name"], "graders": e["graders"],
                      "split": e["split"], **block}
    tasks = []
    by_task: Dict[str, List[Dict]] = defaultdict(list)
    for r in rows:
        by_task[r["id"]].append(r)
    for tid, rs in by_task.items():
        r0 = rs[0]
        tasks.append({"eval_id": r0["eval_id"], "task_id": tid, "property": r0["property"],
                      "origin": r0["origin"], "grader": r0["grader"],
                      "trials": len(rs), "passes": sum(bool(r["passed"]) for r in rs),
                      "passed": all(r["passed"] for r in rs),
                      "error": next((r["error"] for r in rs if r.get("error")), None)})
    return {
        "run_id": run_id,
        "toolkit_version": toolkit_version(),
        "git_sha": git_sha(),
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "trials": trials,
        "evals_selected": selected,
        "cases_dir": str(cases_dir),
        "overall": overall,
        "evals": evals,
        "tasks": tasks,
        "_reading": {
            "n": "graded samples = tasks x trials; recall = vuln/ detected / n, precision = "
                 "clean/ not detected / n; *_ci95 is the Wilson score interval over n",
            "passed": "samples where vuln/ was detected AND clean/ was not, with no grader error",
            "pass_at_k": "trials > 1 only: mean over tasks of the unbiased pass@k estimator",
            "pass_pow_k": "trials > 1 only: mean over tasks of p**k (tau-bench consistency)",
            "historical_misses": "distinct tasks whose origin is historical-miss",
        },
    }


# ----------------------------------------------------------------- report

def render_report(summary: Dict, rows: List[Dict]) -> str:
    o = summary["overall"]
    trials = summary.get("trials", 1)
    lines = [f"# Evals — security-agents {summary['toolkit_version']} · run `{summary['run_id']}`", "",
             f"Tasks: {o['tasks']} · trials: {trials} · samples: {o['n']} · passed: {o['passed']} · "
             f"errors: {o['errors']} · historical misses encoded: {o['historical_misses']}", "",
             f"**Overall recall {fmt_ci(o['recall'] or 0, o['recall_ci95'] or (0, 0))} · "
             f"precision {fmt_ci(o['precision'] or 0, o['precision_ci95'] or (0, 0))}**"
             + (f" · pass^{trials} {o.get('pass_pow_k', {}).get(str(trials))}" if trials > 1 else ""),
             "", "Recall is the vuln/ twin detected; precision is the clean/ twin not detected "
             "(the clean twin is the baseline scored alongside). CIs are Wilson 95%.", ""]
    head = "| eval | property | tasks | n | recall | precision | errors | historical misses |"
    sep = "|---|---|---|---|---|---|---|---|"
    if trials > 1:
        head += f" pass@{trials} | pass^{trials} |"
        sep += "---|---|"
    lines += [head, sep]
    for eid, b in summary["evals"].items():
        if not b["n"]:
            lines.append(f"| {eid} | {b['property']} | 0 | 0 | — | — | 0 | 0 |" + (" — | — |" if trials > 1 else ""))
            continue
        row = (f"| {eid} | {b['property']} | {b['tasks']} | {b['n']} | "
               f"{fmt_ci(b['recall'], b['recall_ci95'])} | {fmt_ci(b['precision'], b['precision_ci95'])} | "
               f"{b['errors']} | {b['historical_misses']} |")
        if trials > 1:
            row += f" {b.get('pass_at_k', {}).get(str(trials), '—')} | {b.get('pass_pow_k', {}).get(str(trials), '—')} |"
        lines.append(row)
    lines += ["", "| task | eval | origin | grader | trial | vuln detected | clean detected | result |",
              "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        res = "ERROR: " + str(r["error"])[:60] if r.get("error") else ("pass" if r["passed"] else "FAIL")
        lines.append(f"| {r['id']} | {r.get('eval_id')} | {r['origin']} | {r['grader']} | {r.get('trial', 1)} | "
                     f"{r.get('vuln', {}).get('detected')} | {r.get('clean', {}).get('detected')} | {res} |")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- entry point

def run(cases_dir: Path, out_dir: Path, *, evals: Optional[List[str]] = None, trials: int = 1,
        only: Optional[str] = None, quiet: bool = False) -> Dict:
    """Grade, write the run directory, return the summary (with `run_dir` added)."""
    if trials < 1:
        raise ValueError("--trials must be >= 1")
    registry = load_registry()
    selected = select(registry, evals) if evals else list(registry)
    by_prop = {registry[e]["property"]: e for e in selected}
    cases = [c for c in discover(cases_dir) if c.property in by_prop]
    if only:
        keep = set(only.split(","))
        cases = [c for c in cases if c.id in keep or c.property in keep]
        # a narrowed run reports only the evals it touched, not nine empty rows
        touched = {c.property for c in cases}
        selected = [e for e in selected if registry[e]["property"] in touched]
    graders = default_graders(REPO)

    run_id = make_run_id()
    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    rows: List[Dict] = []
    with (run_dir / "samples.jsonl").open("w") as fh:
        for c in cases:
            for t in range(1, trials + 1):
                row = grade_case(c, graders)
                row.update({"trial": t, "eval_id": by_prop[c.property]})
                rows.append(row)
                for s in samples_from_row(row):
                    fh.write(json.dumps(s, sort_keys=True, default=str) + "\n")
    summary = build_summary(rows, registry, run_id=run_id, trials=trials, selected=selected,
                            cases_dir=cases_dir)
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=1, default=str))
    report = render_report(summary, rows)
    (run_dir / "report.md").write_text(report)
    shown = run_dir.resolve()
    shown = shown.relative_to(REPO) if shown.is_relative_to(REPO) else shown
    (out_dir / "latest.json").write_text(json.dumps(
        {"run_id": run_id, "path": str(shown), "generated": summary["generated"]}, indent=1))
    if not quiet:
        print(report)
        print(f"wrote {run_dir}")
    summary["run_dir"] = str(run_dir)
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals run", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--eval", action="append", default=None, metavar="ID",
                    help="eval to run (id, name or property); repeatable, comma-separated ok")
    ap.add_argument("--trials", type=int, default=1, help="trials per task (default 1)")
    ap.add_argument("--out", default=str(RESULTS), metavar="DIR",
                    help="results directory; the run goes in DIR/<run_id>/ (default evals/results)")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any failed or errored task")
    ap.add_argument("--only", default=None, help="comma-separated case ids or properties")
    ap.add_argument("--cases", default=str(REPO / "evals" / "cases"))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    evals = [e for grp in (args.eval or []) for e in grp.split(",") if e] or None
    summary = run(Path(args.cases), Path(args.out), evals=evals, trials=args.trials,
                  only=args.only, quiet=args.quiet)
    o = summary["overall"]
    if args.strict and (o["passed"] != o["n"] or o["errors"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
