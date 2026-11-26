"""One CLI for the evals (Layer 6):

    python -m evals run [--eval ID ...] [--trials K] [--out DIR] [--strict] [--only ...]
    python -m evals list                       # evals, case counts, graders
    python -m evals card <name> [--write]      # eval card (--all for every one)
    python -m evals build-tasks [--check]      # regenerate evals/registry/tasks.jsonl
    python -m evals agent-validate --repo <name|all> [--only ids] [--mode auto|container|local] [--out DIR]
    python -m evals agent-run --repo <name|all> --model <id> --trials K --budget-usd N [--only ids] [--mode ...] [--out DIR]
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from typing import List

from .registry import TASKS_FILE, REPO, build_tasks, load_registry, render_tasks, tasks_are_fresh
from .run import discover

USAGE = __doc__


def cmd_list(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals list")
    ap.parse_args(argv)
    registry = load_registry()
    cases = discover(REPO / "evals" / "cases")
    n = Counter(c.property for c in cases)
    hist = Counter(c.property for c in cases if c.origin == "historical-miss")
    graders = {}
    for c in cases:
        graders.setdefault(c.property, set()).add(c.grader)
    rows = [("eval", "property", "tasks", "hist", "graders", "split", "owner agent")]
    for eid, e in registry.items():
        p = e["property"]
        rows.append((eid, p, str(n.get(p, 0)), str(hist.get(p, 0)),
                     ", ".join(sorted(graders.get(p, set()))), e["split"], e["owner_agent"]))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for i, r in enumerate(rows):
        print("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())
        if i == 0:
            print("  ".join("-" * w for w in widths))
    print(f"\n{len(registry)} evals · {len(cases)} tasks · {sum(hist.values())} historical misses")
    return 0


def cmd_build_tasks(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals build-tasks")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed tasks.jsonl is stale; write nothing")
    args = ap.parse_args(argv)
    records = build_tasks(discover(REPO / "evals" / "cases"))
    shown = TASKS_FILE.relative_to(REPO) if TASKS_FILE.is_relative_to(REPO) else TASKS_FILE
    if args.check:
        if tasks_are_fresh(records, TASKS_FILE):
            print(f"{shown} is fresh ({len(records)} tasks)")
            return 0
        print(f"{shown} is stale: run `python -m evals build-tasks`", file=sys.stderr)
        return 1
    TASKS_FILE.write_text(render_tasks(records))
    print(f"wrote {shown} ({len(records)} tasks)")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE.strip())
        return 0 if argv else 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "run":
        from .run import main as run_main
        return run_main(rest)
    if cmd == "list":
        return cmd_list(rest)
    if cmd == "card":
        from .cards import main as card_main
        return card_main(rest)
    if cmd == "build-tasks":
        return cmd_build_tasks(rest)
    if cmd == "agent-run":
        from .agent.runner import main_run as agent_run_main
        return agent_run_main(rest)
    if cmd == "agent-validate":
        from .agent.runner import main_validate as agent_validate_main
        return agent_validate_main(rest)
    print(f"unknown command {cmd!r}\n\n{USAGE.strip()}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
