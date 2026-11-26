"""Mutation testing of a project's security regression net.

Question answered: if a fixed security bug were silently reintroduced, would the
test suite go red?  Each mutation reverts one fix; the runner applies it in a
throwaway worktree, runs the project's security tests, and records whether they
caught it.  The metric is the kill rate (killed / mutations).  A *survivor* is a
real gap in the regression net.

    python -m evals.mutate --repo ~/Developer/projects/foo
    python -m evals.mutate --repo ~/Developer/projects/foo --strict      # exit 1 on survivor/error
    python -m evals.mutate --repo ... --mutations path/to/mutations.yaml --only P2,P7-child-env

Schema of `<repo>/security/mutations.yaml`:

    test: ".venv/bin/python -m pytest tests/security -q -x"   # default command for every mutation
    pythonpath: ["."]                  # optional; dirs (relative to the repo) put on PYTHONPATH
    mutations:
      - id: P2-redact-spaces           # unique
        property: P2                   # P0..P9, used for the per-property kill rate
        description: reintroduce the ambiguous whitespace prefix in the cookie-header regex
        file: scripts/redact.py        # relative to the repo root
        find: "[ \\t]*(?:-[ \\t]*)?"   # literal text; must occur EXACTLY once in the file
        replace: "[ \\t]*-?[ \\t]*"    # literal replacement (the pre-fix code)
        test: optional per-mutation override of the command

Mechanics, in order, for each mutation:

  1. `git worktree add --detach <tmp> HEAD` of the target repo.  The target's own
     working tree is never modified and tests never run in it.  Because the
     worktree is built from HEAD, uncommitted changes in the target are not seen.
  2. Apply `find` -> `replace` to `file`.  If `find` occurs 0 or more than 1 times,
     or `replace` equals `find`, the mutation is recorded as `error` (never
     silently applied somewhere else).
  3. Run the test command with cwd = the worktree.  The first argv token is the
     interpreter; when it is a relative path (`.venv/bin/python`) it is resolved
     against the *target repo*, because virtualenvs are gitignored and absent
     from the worktree.  The worktree (plus `pythonpath`) is prepended to
     PYTHONPATH so an editable install of the project in that venv cannot win
     the import race and quietly test the unmutated main tree.
  4. exit != 0 -> `killed`; exit == 0 -> `survived`; timeout or any failure to set
     the mutation up -> `error`.  Default timeout 600 s per mutation.
  5. `git worktree remove --force <tmp>`, always.

Before any mutation runs, the same command is run once on an unmutated worktree
(the *baseline*).  A red baseline would make every mutation look killed, so the
run aborts instead (`--no-baseline` to skip when you know what you are doing).

Output: `evals/results/mutation-<repo-name>.json` and `.md` (table of id,
property, result, seconds, and the test tail for survivors/errors; kill rate
overall and per property).  `--strict` exits 1 on any survivor or error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

REPO = Path(__file__).resolve().parents[1]
DEFAULT_TIMEOUT = 600
TAIL_LINES = 25


class MutationSpecError(ValueError):
    """The mutations file is malformed (schema), as opposed to a mutation that
    cannot be applied (which is recorded as an `error` row, not raised)."""


@dataclass
class Mutation:
    id: str
    property: str
    file: str
    find: str
    replace: str
    description: str = ""
    test: Optional[str] = None


@dataclass
class Spec:
    test: str
    mutations: List[Mutation]
    pythonpath: List[str] = field(default_factory=lambda: ["."])


@dataclass
class Outcome:
    id: str
    property: str
    result: str                      # killed | survived | error
    seconds: float
    description: str = ""
    exit_code: Optional[int] = None
    detail: str = ""                 # error reason, or test tail for survived/error
    test: str = ""


# ----------------------------------------------------------------- spec

def load_spec(path: Path) -> Spec:
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except FileNotFoundError:
        raise MutationSpecError(f"{path} does not exist")
    if not isinstance(data, dict):
        raise MutationSpecError(f"{path}: top level must be a mapping")
    test = data.get("test")
    raw = data.get("mutations")
    if not isinstance(raw, list) or not raw:
        raise MutationSpecError(f"{path}: 'mutations' must be a non-empty list")
    pythonpath = data.get("pythonpath", ["."])
    if not isinstance(pythonpath, list) or not all(isinstance(p, str) for p in pythonpath):
        raise MutationSpecError(f"{path}: 'pythonpath' must be a list of strings")

    muts: List[Mutation] = []
    seen = set()
    for i, m in enumerate(raw):
        if not isinstance(m, dict):
            raise MutationSpecError(f"{path}: mutations[{i}] must be a mapping")
        missing = [k for k in ("id", "property", "file", "find", "replace") if k not in m]
        if missing:
            raise MutationSpecError(f"{path}: mutations[{i}] missing {missing}")
        mid = str(m["id"])
        if mid in seen:
            raise MutationSpecError(f"{path}: duplicate mutation id {mid!r}")
        seen.add(mid)
        cmd = m.get("test", test)
        if not cmd or not isinstance(cmd, str):
            raise MutationSpecError(f"{path}: mutation {mid!r} has no test command "
                                    f"(set top-level 'test' or a per-mutation override)")
        for k in ("find", "replace", "file"):
            if not isinstance(m[k], str):
                raise MutationSpecError(f"{path}: mutation {mid!r}: {k!r} must be a string")
        muts.append(Mutation(id=mid, property=str(m["property"]), file=m["file"],
                             find=m["find"], replace=m["replace"],
                             description=str(m.get("description", "")), test=cmd))
    return Spec(test=test or "", mutations=muts, pythonpath=pythonpath)


# ----------------------------------------------------------------- git

def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=check)


def main_checkout(repo: Path) -> Path:
    """The primary working tree of `repo`. When `repo` is itself a linked worktree, gitignored
    assets (the virtualenv) live in the main checkout, so commands resolve against it too."""
    r = _git(repo, "rev-parse", "--git-common-dir", check=False)
    if r.returncode != 0:
        return repo
    common = Path(r.stdout.strip())
    if not common.is_absolute():
        common = (repo / common).resolve()
    return common.parent if common.name == ".git" else repo


def add_worktree(repo: Path, parent: Path, name: str) -> Path:
    wt = parent / name
    _git(repo, "worktree", "add", "--detach", "--quiet", str(wt), "HEAD")
    return wt


def remove_worktree(repo: Path, wt: Path) -> None:
    _git(repo, "worktree", "remove", "--force", str(wt), check=False)
    if wt.exists():                       # git refused (e.g. nested untracked junk)
        shutil.rmtree(wt, ignore_errors=True)
        _git(repo, "worktree", "prune", check=False)


# ----------------------------------------------------------------- apply

def apply_mutation(wt: Path, m: Mutation) -> None:
    """Rewrite `m.file` in the worktree. Raises ValueError when the edit cannot be
    made unambiguously — that is the `find`-count guard."""
    target = (wt / m.file)
    if not target.is_file():
        raise ValueError(f"file {m.file!r} does not exist in the repo")
    if m.find == m.replace:
        raise ValueError("replace equals find: the mutation is a no-op")
    text = target.read_text()
    n = text.count(m.find)
    if n != 1:
        raise ValueError(f"find occurs {n} times in {m.file} (must be exactly 1)")
    target.write_text(text.replace(m.find, m.replace, 1))


# ----------------------------------------------------------------- run

def resolve_command(cmd: str, repo: Path) -> List[str]:
    """shlex-split; a relative interpreter path (`.venv/bin/python`) is resolved
    against the target repo, then against its main checkout when the target is a
    linked worktree, since venvs are gitignored and missing in worktrees."""
    argv = shlex.split(cmd)
    if not argv:
        raise ValueError("empty test command")
    head = argv[0]
    if ("/" in head or head.startswith(".")) and not os.path.isabs(head):
        for base in (repo, main_checkout(repo)):
            # abspath, not resolve(): following the venv's bin/python symlink to the
            # base interpreter would silently drop the virtualenv.
            cand = os.path.abspath(base / head)
            if os.path.exists(cand):
                argv[0] = cand
                break
        else:
            raise FileNotFoundError(f"interpreter {head!r} not found under {repo} or {main_checkout(repo)}")
    return argv


def run_tests(cmd: str, repo: Path, wt: Path, pythonpath: List[str],
              timeout: int) -> "tuple[Optional[int], str, bool]":
    """-> (exit code or None on timeout, combined output, timed_out)."""
    argv = resolve_command(cmd, repo)
    env = dict(os.environ)
    pp = [str((wt / p).resolve()) for p in pythonpath]
    if env.get("PYTHONPATH"):
        pp.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pp)
    env.pop("PYTEST_ADDOPTS", None)
    proc = subprocess.Popen(argv, cwd=str(wt), env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out or "", False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        out, _ = proc.communicate()
        return None, out or "", True


def tail(text: str, n: int = TAIL_LINES) -> str:
    lines = text.rstrip().splitlines()
    return "\n".join(lines[-n:])


def run_one(repo: Path, m: Mutation, spec: Spec, scratch: Path, timeout: int) -> Outcome:
    t0 = time.monotonic()
    wt: Optional[Path] = None
    try:
        wt = add_worktree(repo, scratch, m.id)
        try:
            apply_mutation(wt, m)
        except ValueError as e:
            return Outcome(m.id, m.property, "error", round(time.monotonic() - t0, 1),
                           m.description, None, f"not applied: {e}", m.test or "")
        rc, out, timed_out = run_tests(m.test or spec.test, repo, wt, spec.pythonpath, timeout)
        secs = round(time.monotonic() - t0, 1)
        if timed_out:
            return Outcome(m.id, m.property, "error", secs, m.description, None,
                           f"timeout after {timeout}s\n" + tail(out), m.test or "")
        if rc == 0:
            return Outcome(m.id, m.property, "survived", secs, m.description, rc, tail(out), m.test or "")
        return Outcome(m.id, m.property, "killed", secs, m.description, rc, "", m.test or "")
    except (subprocess.CalledProcessError, OSError) as e:
        detail = getattr(e, "stderr", "") or str(e)
        return Outcome(m.id, m.property, "error", round(time.monotonic() - t0, 1),
                       m.description, None, f"setup failed: {detail.strip()}", m.test or "")
    finally:
        if wt is not None:
            remove_worktree(repo, wt)


def run_baseline(repo: Path, spec: Spec, scratch: Path, timeout: int) -> Dict:
    t0 = time.monotonic()
    wt = add_worktree(repo, scratch, "baseline")
    try:
        rc, out, timed_out = run_tests(spec.test, repo, wt, spec.pythonpath, timeout)
    finally:
        remove_worktree(repo, wt)
    return {"exit_code": rc, "passed": (rc == 0 and not timed_out), "timed_out": timed_out,
            "seconds": round(time.monotonic() - t0, 1), "tail": tail(out)}


# ----------------------------------------------------------------- report

def summarize(rows: List[Outcome]) -> Dict:
    by: Dict[str, Dict] = defaultdict(lambda: {"mutations": 0, "killed": 0, "survived": 0, "errors": 0})
    for r in rows:
        b = by[r.property]
        b["mutations"] += 1
        b["killed"] += r.result == "killed"
        b["survived"] += r.result == "survived"
        b["errors"] += r.result == "error"
    out = {}
    for p, b in sorted(by.items()):
        out[p] = {**b, "kill_rate": round(b["killed"] / b["mutations"], 3) if b["mutations"] else None}
    n = len(rows)
    k = sum(r.result == "killed" for r in rows)
    out["_overall"] = {"mutations": n, "killed": k,
                       "survived": sum(r.result == "survived" for r in rows),
                       "errors": sum(r.result == "error" for r in rows),
                       "kill_rate": round(k / n, 3) if n else None}
    return out


def render_md(repo_name: str, head: str, summary: Dict, rows: List[Outcome], baseline: Optional[Dict]) -> str:
    o = summary["_overall"]
    lines = [f"# Mutation testing — {repo_name} @ {head[:12]}", "",
             f"Mutations: {o['mutations']} · killed: {o['killed']} · survived: {o['survived']} · "
             f"errors: {o['errors']}", "",
             f"**Kill rate {o['kill_rate']}**", ""]
    if baseline is not None:
        lines += [f"Baseline (unmutated) exit {baseline['exit_code']} in {baseline['seconds']}s — "
                  f"{'green' if baseline['passed'] else 'RED'}", ""]
    lines += ["| property | mutations | killed | survived | errors | kill rate |",
              "|---|---|---|---|---|---|"]
    for p, b in summary.items():
        if p == "_overall":
            continue
        lines.append(f"| {p} | {b['mutations']} | {b['killed']} | {b['survived']} | {b['errors']} | {b['kill_rate']} |")
    lines += ["", "| id | property | result | seconds | description |", "|---|---|---|---|---|"]
    for r in rows:
        res = r.result.upper() if r.result != "killed" else "killed"
        lines.append(f"| {r.id} | {r.property} | {res} | {r.seconds} | {r.description} |")
    bad = [r for r in rows if r.result != "killed"]
    if bad:
        lines += ["", "## Survivors and errors", ""]
        for r in bad:
            lines += [f"### {r.id} — {r.result}", "", f"`{r.test}`", "", "```", r.detail, "```", ""]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- main

def run(repo: Path, mutations_path: Path, out: Optional[Path] = None, *, strict: bool = False,
        timeout: int = DEFAULT_TIMEOUT, only: Optional[str] = None, baseline: bool = True,
        quiet: bool = False) -> int:
    repo = repo.resolve()
    if not (repo / ".git").exists():
        raise MutationSpecError(f"{repo} is not a git repository")
    spec = load_spec(mutations_path)
    muts = spec.mutations
    if only:
        keep = set(only.split(","))
        muts = [m for m in muts if m.id in keep or m.property in keep]
    head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    repo_name = main_checkout(repo).name

    scratch = Path(tempfile.mkdtemp(prefix=f"mutate-{repo_name}-"))
    rows: List[Outcome] = []
    base: Optional[Dict] = None
    try:
        if baseline:
            if not spec.test:
                raise MutationSpecError("baseline needs a top-level 'test' command (or pass --no-baseline)")
            try:
                base = run_baseline(repo, spec, scratch, timeout)
            except (OSError, subprocess.CalledProcessError) as e:
                print(f"BASELINE could not run: {getattr(e, 'stderr', '') or e}", file=sys.stderr)
                return 2
            if not base["passed"]:
                print(f"BASELINE RED (exit {base['exit_code']}) — every mutation would look killed; aborting.\n"
                      + base["tail"], file=sys.stderr)
                return 2
            if not quiet:
                print(f"baseline green in {base['seconds']}s")
        for m in muts:
            r = run_one(repo, m, spec, scratch, timeout)
            rows.append(r)
            if not quiet:
                print(f"{r.result:<9} {r.id}  ({r.seconds}s)")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        _git(repo, "worktree", "prune", check=False)

    summary = summarize(rows)
    payload = {"repo": repo_name, "repo_path": str(repo), "head": head,
               "mutations_file": str(mutations_path),
               "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
               "baseline": base, "summary": summary,
               "mutations": [r.__dict__ for r in rows]}
    out = out or (REPO / "evals" / "results" / f"mutation-{repo_name}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=1))
    md = render_md(repo_name, head, summary, rows, base)
    out.with_suffix(".md").write_text(md)
    if not quiet:
        print(md)
        print(f"wrote {out}")

    if strict and any(r.result != "killed" for r in rows):
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True, help="path to the target git repository")
    ap.add_argument("--mutations", default=None, help="default <repo>/security/mutations.yaml")
    ap.add_argument("--out", default=None, help="JSON path (default evals/results/mutation-<repo>.json)")
    ap.add_argument("--strict", action="store_true", help="exit 1 on any survivor or error")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="seconds per mutation")
    ap.add_argument("--only", default=None, help="comma-separated mutation ids or properties")
    ap.add_argument("--no-baseline", action="store_true", help="skip the unmutated sanity run")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    repo = Path(args.repo)
    mutations = Path(args.mutations) if args.mutations else repo / "security" / "mutations.yaml"
    try:
        return run(repo, mutations, Path(args.out) if args.out else None, strict=args.strict,
                   timeout=args.timeout, only=args.only, baseline=not args.no_baseline,
                   quiet=args.quiet)
    except MutationSpecError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
