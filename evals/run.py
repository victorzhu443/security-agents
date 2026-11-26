"""Run every case: grade vuln/ and clean/, compute recall and precision per
property, write JSON + Markdown.

    python -m evals.run                      # report, exit 0 (Phase 1: no gates)
    python -m evals.run --strict             # exit 1 on any failed/errored case
    python -m evals.run --out evals/results/x.json --cases evals/cases
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import yaml

from .graders import Case, Result, default_graders

REPO = Path(__file__).resolve().parents[1]


def toolkit_version() -> str:
    """The version in this checkout's pyproject (install metadata can be stale)."""
    m = re.search(r'^version\s*=\s*"([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
    return m.group(1) if m else "unknown"


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
                          description=data.get("description", "")))
    return cases


def grade_case(case: Case, graders) -> Dict:
    g = graders.get(case.grader)
    if g is None:
        return {"id": case.id, "property": case.property, "origin": case.origin,
                "grader": case.grader, "error": f"unknown grader {case.grader!r}", "passed": False}
    rv: Result = g.grade(case, "vuln")
    rc: Result = g.grade(case, "clean")
    error = rv.error or rc.error
    passed = (error is None) and rv.detected and not rc.detected
    return {
        "id": case.id, "property": case.property, "origin": case.origin, "grader": case.grader,
        "description": case.description,
        "vuln": {"detected": rv.detected, "metrics": rv.metrics, "evidence": rv.evidence},
        "clean": {"detected": rc.detected, "metrics": rc.metrics, "evidence": rc.evidence},
        "error": error, "passed": passed,
        # recall counts a case once if vuln was detected; precision if clean was not
        "recall_hit": bool(rv.detected and not rv.error),
        "precision_hit": bool((not rc.detected) and not rc.error),
    }


def summarize(rows: List[Dict]) -> Dict:
    by: Dict[str, Dict] = defaultdict(lambda: {"cases": 0, "recall_hits": 0, "precision_hits": 0,
                                               "errors": 0, "historical_misses": 0})
    for r in rows:
        b = by[r["property"]]
        b["cases"] += 1
        b["recall_hits"] += int(r.get("recall_hit", False))
        b["precision_hits"] += int(r.get("precision_hit", False))
        b["errors"] += int(bool(r.get("error")))
        b["historical_misses"] += int(r.get("origin") == "historical-miss")
    out = {}
    for p, b in sorted(by.items()):
        n = b["cases"]
        out[p] = {**b, "recall": round(b["recall_hits"] / n, 3) if n else None,
                  "precision": round(b["precision_hits"] / n, 3) if n else None}
    n = len(rows)
    out["_overall"] = {
        "cases": n,
        "recall": round(sum(r.get("recall_hit", False) for r in rows) / n, 3) if n else None,
        "precision": round(sum(r.get("precision_hit", False) for r in rows) / n, 3) if n else None,
        "passed": sum(r["passed"] for r in rows),
        "errors": sum(bool(r.get("error")) for r in rows),
        "historical_misses": sum(r.get("origin") == "historical-miss" for r in rows),
    }
    return out


def render_md(version: str, summary: Dict, rows: List[Dict]) -> str:
    o = summary["_overall"]
    lines = [f"# Evals — security-agents {version}", "",
             f"Cases: {o['cases']} · passed: {o['passed']} · errors: {o['errors']} · "
             f"historical misses encoded: {o['historical_misses']}", "",
             f"**Overall recall {o['recall']} · precision {o['precision']}**", "",
             "| property | cases | recall | precision | errors |", "|---|---|---|---|---|"]
    for p, b in summary.items():
        if p == "_overall":
            continue
        lines.append(f"| {p} | {b['cases']} | {b['recall']} | {b['precision']} | {b['errors']} |")
    lines += ["", "| case | property | origin | grader | vuln detected | clean detected | result |",
              "|---|---|---|---|---|---|---|"]
    for r in rows:
        res = "ERROR: " + str(r["error"])[:60] if r.get("error") else ("pass" if r["passed"] else "FAIL")
        lines.append(f"| {r['id']} | {r['property']} | {r['origin']} | {r['grader']} | "
                     f"{r.get('vuln', {}).get('detected')} | {r.get('clean', {}).get('detected')} | {res} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(REPO / "evals" / "cases"))
    ap.add_argument("--out", default=None, help="JSON path (default evals/results/<version>.json)")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any failed or errored case")
    ap.add_argument("--only", default=None, help="comma-separated case ids or properties")
    args = ap.parse_args(argv)

    cases = discover(Path(args.cases))
    if args.only:
        keep = set(args.only.split(","))
        cases = [c for c in cases if c.id in keep or c.property in keep]
    graders = default_graders(REPO)
    rows = [grade_case(c, graders) for c in cases]
    summary = summarize(rows)
    version = toolkit_version()
    payload = {"toolkit_version": version, "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
               "summary": summary, "cases": rows}

    out = Path(args.out) if args.out else REPO / "evals" / "results" / f"{version}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=1))
    (out.parent / "latest.md").write_text(render_md(version, summary, rows))
    print(render_md(version, summary, rows))
    print(f"wrote {out}")

    bad = [r for r in rows if not r["passed"]]
    if args.strict and bad:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
