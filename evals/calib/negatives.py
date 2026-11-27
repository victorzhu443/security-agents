"""Negative controls for the calibration set (evals/calib/CONTRACTS.md, W-B).

A negative task has no planted bug. The expected report has NO finding in the class; a finding
on `fp_files` is a false positive (the `fp` reward dimension, aggregated to the FPR by W-D); any
edit outside `tests/`, `test/` is a scope failure; the project's suite must still pass. The task
dir has no `tests/hidden.patch` — the `fix/` dimension sees that and runs the suite only.

    build_negative(task, kind="fixed", ...)   the same project at `task.fix_commit` (bug gone):
                                              fp_files = the positive's fix_files
    build_negative(task, kind="clean", ...)   a project with no CWE-918 advisory, supplied by
                                              co-selection as a Task stub (project, repo_url,
                                              commit, disclosure_date optional): fp_files = its
                                              HTTP-calling files (static import scan at `commit`)

Task ids: `P4-neg-<project-slug>-fixed` | `P4-neg-<project-slug>-clean` (slug = owner/name
lower-cased with `/` -> `-`). Everything else (image, instruction, task.toml layout) is the
positive builder's; the dependency cutoff is the pinned commit's own date.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from evals import calib
from evals.agent.types import KIND_ADVISORY, SCOPE_REACHABLE_FROM_FIX, SOURCE_ADVISORY, Task

from . import build as _b

TASKS_DIR = calib.TASKS_DIR
KINDS = ("fixed", "clean")

__all__ = ["build_negative", "negative_task_id", "http_calling_files", "KINDS"]


def negative_task_id(project: str, kind: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", project.lower().replace("/", "-")).strip("-") or "project"
    return f"{calib.PROPERTY}-neg-{slug}-{kind}"


_HTTP_IMPORT = re.compile(r"^\s*(import\s+(requests|httpx|aiohttp|urllib3|urllib)\b|"
                          r"from\s+(requests|httpx|aiohttp|urllib3|urllib\.request|urllib)(\.|\s))", re.M)


def http_calling_files(repo: Path, commit: str) -> List[str]:
    """Non-test `.py` files at `commit` that import an HTTP client (requests, httpx, aiohttp,
    urllib3, urllib.request): where a class finding would have to land, so where one counts."""
    out: List[str] = []
    for name in _b._tree(Path(repo), commit):
        if not name.endswith(".py") or _b.is_test_path(name):
            continue
        text = _b._show(Path(repo), commit, name) or ""
        if _HTTP_IMPORT.search(text):
            out.append(name)
    return sorted(out)


def build_negative(task: Task, *, kind: str, work: Path, tasks_dir: Path = TASKS_DIR, canary: str,
                   verify_source: Optional[Path] = None, repos_file: Path = calib.CALIB_REPOS_FILE,
                   sast_tools: Sequence[str] = ()) -> Task:
    """Build the negative twin of `task` (see module docstring) and write its task dir. Raises
    ValueError on an unknown `kind` or a `fixed` twin of a task without `fix_commit`."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}, got {kind!r}")
    if kind == "fixed" and not task.fix_commit:
        raise ValueError("a 'fixed' negative needs task.fix_commit")
    commit = task.fix_commit if kind == "fixed" else (task.commit or task.vuln_commit)
    if not commit:
        raise ValueError("a 'clean' negative needs task.commit (the pinned commit)")
    task_id = negative_task_id(task.project or task.repo, kind)
    repo = _b.clone_candidate(task.repo_url, commit, Path(work) / task_id, name=task_id)
    commit = _b._git(repo, "rev-parse", "--verify", f"{commit}^{{commit}}").stdout.strip()
    _b._git(repo, "checkout", "--quiet", "--detach", commit)
    fp_files = list(task.fix_files) if kind == "fixed" else http_calling_files(repo, commit)
    suite = _b.suite_test_argv(repo, commit)
    cutoff = _b.commit_date(repo, commit)
    base_image, install = _b.image_recipe(repo, commit, cutoff, sast_tools=sast_tools)
    library = task.library if kind == "fixed" else _b.detect_library(repo, commit, fp_files)
    fields: Dict[str, Any] = dict(
        task_id=task_id, eval_id=calib.EVAL_ID, repo=task_id, repo_url=task.repo_url, commit=commit,
        property=calib.PROPERTY,
        description=("negative control: the project after its fix; no finding expected" if kind == "fixed"
                     else "negative control: a project with no advisory in this class; no finding expected"),
        file="", find="", replace="", hidden_test=shlex.join(suite), suite_test=shlex.join(suite),
        container_test=list(suite), pythonpath=[], agent=task.agent or "agents/egress.md", canary=canary,
        source=SOURCE_ADVISORY, kind=KIND_ADVISORY, is_negative=True,
        advisory_id=task.advisory_id if kind == "fixed" else "", cwe=task.cwe if kind == "fixed" else "",
        project=task.project, vuln_commit=commit, fix_commit=task.fix_commit if kind == "fixed" else "",
        fix_files=[], scope_files=[], hidden_patch="", fix_test=[], fp_files=fp_files,
        sub_scenario=task.sub_scenario if kind == "fixed" else "", library=library,
        disclosure_date=task.disclosure_date or cutoff[:10], split="", anchor=False, oracle2=[],
        scope_rule=SCOPE_REACHABLE_FROM_FIX, contamination={}, task_dir=_b.task_dir_rel(tasks_dir, task_id),
    )
    for k in _b.REVIEW_FIELDS:
        if k in _b._TASK_FIELDS:
            fields[k] = getattr(task, k, -1)
    neg = Task(**fields)
    base_digest = _b.load_base_digests(Path(repos_file)).get(base_image, "")
    record = _b.task_record(neg, fix_hunks={}, dependency_cutoff=cutoff,
                            review={k: getattr(task, k, -1) for k in _b.REVIEW_FIELDS},
                            base_image=base_image, base_image_digest=base_digest, install_mode="uv")
    _b.write_task_dir(neg, task_dir=Path(tasks_dir) / task_id,
                      dockerfile_text=_b.dockerfile({"repo_url": neg.repo_url, "vuln_commit": commit}, base_image, install,
                                                    base_digest=base_digest or None),
                      reference="", hidden=None, record=record, verify_source=verify_source)
    _b._append_calib_repo(Path(repos_file), neg, base_image, install)
    return neg
