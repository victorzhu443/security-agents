"""Task records from the project repos' `security/mutations.yaml` catalogues (Phase 7, W3).

One `Task` per mutation, in catalogue order, pinned to the commit in `repos.yaml`. The
catalogue text comes from `repos.catalogue_text(cfg)` (a read-only `git show` at the pinned
commit; never the working tree) and is parsed by `evals.mutate.load_spec`, so the schema
and its guards (unique ids, every mutation has a test command) are the ones the mutation
runner already enforces.

    map_test_command(cmd)              host test command -> container argv
    load_tasks(cfg, catalogue_text=)   one RepoConfig -> [Task] (source = real-codebase)
    load_all_tasks("all")              repo name -> [Task] via repos.select_repos
    tasks_jsonl(tasks)                 one Task.to_record() JSON per line
    filter_tasks(tasks, only)          comma-separated ids or properties (mutate.py --only)

Test-command mapping table
--------------------------

The catalogue's `test` names the *host* interpreter of the repo's security venv. Inside the
container the clone is mounted at `/work` (the cwd of every `exec`) and the interpreter on
PATH is `python` (`types.CONTAINER_PYTHON`), so `map_test_command` replaces argv[0] and
keeps the rest of the command verbatim. The interpreter forms present in the four
catalogues at their pinned commits, and what each becomes:

    catalogue argv[0]                                               container argv[0]  cwd
    .venv/bin/python           (research-replication-agent,         python             /work
                                firstplay-backend)
    .venv-sec/bin/python       (smart-dispatch)                     python             /work
    /Users/vzhu/Developer/projects/study-hub/.venv-sec/bin/python   python             /work
                               (study-hub)

    rest of the command, every catalogue:  -m pytest tests/security -q -x -p no:cacheprovider
    (kept verbatim; per-mutation `test` overrides are mapped the same way)

A token counts as an interpreter when its basename is `python`, `python3` or `python3.N`,
or when it is a path ending in `/bin/python*`. Any other argv[0] (`pytest`, `make`, ...) is
left as it is. `pythonpath` (study-hub: `[".", "scripts"]`) is not part of the command; the
environment puts it on PYTHONPATH relative to the clone.

Local mode (docker absent) does not use this table for the fix grader's command: the Env
maps argv[0] `python` back to the host interpreter itself, resolving the catalogue's form
against the local checkout exactly as `evals.mutate.resolve_command` does (venvs are
gitignored, so they exist only in the checkout, never in the clone). Graders therefore
always send the container form (`task.container_test`) and let the Env choose.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .. import registry as _registry
from ..mutate import load_spec
from . import repos as _repos
from .repos import RepoConfig
from .types import AGENT_FOR_PROPERTY, CONTAINER_PYTHON, SOURCE_REAL_CODEBASE, Task

_PYTHON_BASENAME = re.compile(r"^python(3(\.\d+)?)?$")


def is_interpreter_token(token: str) -> bool:
    """True for `python`, `python3`, `python3.12`, and any path ending in `/bin/python*`."""
    parent, _, base = token.rpartition("/")
    if _PYTHON_BASENAME.match(base):
        return True
    return bool(parent) and (parent == "bin" or parent.endswith("/bin")) and base.startswith("python")


def map_test_command(cmd: str) -> List[str]:
    """`.venv/bin/python -m pytest tests/security -q` -> `["python", "-m", "pytest", "tests/security", "-q"]`.

    shlex-split; an interpreter argv[0] (see the module docstring) becomes
    `CONTAINER_PYTHON`; anything else is left untouched. Empty command -> ValueError."""
    argv = shlex.split(cmd)
    if not argv:
        raise ValueError("empty test command")
    if is_interpreter_token(argv[0]):
        argv[0] = CONTAINER_PYTHON
    return argv


def _spec_from_text(text: str, label: str):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".yaml", prefix=f"catalogue-{label}-",
                                      delete=False, encoding="utf-8")
    try:
        tmp.write(text)
        tmp.close()
        return load_spec(Path(tmp.name))
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def load_tasks(cfg: RepoConfig, *, catalogue_text: Optional[str] = None, registry=None) -> List[Task]:
    """One Task per mutation of `cfg`'s catalogue at its pinned commit, in catalogue order.

    `catalogue_text` bypasses git (tests); `registry` is the module whose `canary()` is
    used (default `evals.registry`). A property with no agent is a ValueError naming the
    task: the catalogue must be whole before anything runs."""
    text = catalogue_text if catalogue_text is not None else _repos.catalogue_text(cfg)
    spec = _spec_from_text(text, cfg.name)
    canary = (registry or _registry).canary()
    local = _repos.local_checkout(cfg)
    repo_path = str(local) if local is not None else None
    eval_id = f"security.agent.{cfg.name}.v1"

    tasks: List[Task] = []
    for m in spec.mutations:
        hidden_test = m.test or spec.test
        try:
            agent = AGENT_FOR_PROPERTY[m.property]
        except KeyError:
            raise ValueError(f"{cfg.name}/{m.id}: property {m.property!r} has no agent "
                             f"(known: {', '.join(AGENT_FOR_PROPERTY)})") from None
        tasks.append(Task(
            task_id=m.id, eval_id=eval_id, repo=cfg.name, repo_url=cfg.url, commit=cfg.commit,
            property=m.property, description=m.description, file=m.file, find=m.find,
            replace=m.replace, hidden_test=hidden_test, suite_test=spec.test,
            container_test=map_test_command(hidden_test), pythonpath=list(spec.pythonpath),
            agent=agent, canary=canary, source=SOURCE_REAL_CODEBASE, repo_path=repo_path,
        ))
    return tasks


def load_all_tasks(selector: str = "all", repos: Optional[Dict[str, RepoConfig]] = None) -> Dict[str, List[Task]]:
    """Repo name -> tasks for `all` or a comma-separated list of repo names (typos raise)."""
    return {cfg.name: load_tasks(cfg) for cfg in _repos.select_repos(selector, repos)}


def tasks_jsonl(tasks: Iterable[Task]) -> str:
    return "".join(json.dumps(t.to_record(), sort_keys=True, ensure_ascii=False) + "\n" for t in tasks)


def filter_tasks(tasks: Iterable[Task], only: Optional[str]) -> List[Task]:
    """Keep tasks whose id or property is in the comma-separated `only` (mutate.py `--only`
    semantics: no match is an empty list, since one selector may name another repo's task)."""
    tasks = list(tasks)
    if not only:
        return tasks
    keep = {s.strip() for s in only.split(",") if s.strip()}
    return [t for t in tasks if t.task_id in keep or t.property in keep]
