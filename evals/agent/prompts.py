"""Prompt conditions of the calibration runs (evals/calib Phase 1, W-C) — pre-registered.

    class-blind (primary)    system = agents/generic.md (the shared contract + the nine property
                             CATEGORIES, no methods, no misses); user = "review this repository
                             for security vulnerabilities; fix; report with reproducing oracles".
                             Names no property, no description, no class word.
    class-aware (secondary)  system = the property's agents/<name>.md with the leaking sections
                             stripped; user names the property only — and NEVER
                             `task.description` for an advisory task (it would be advisory text).
    <mode>+no_verifier       the same prompts; `passed` drops claim_fidelity (Scores.requires).

`strip_leakage` is applied to EVERY spec body (runner.agent_body delegates here, so the four-repo
mutation runs stop sending the "miss this agent exists to prevent" paragraph to the model too).
`prompt_hashes` pins both texts in the registry entry; a drift shows up as a hash change.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple

from .types import KIND_ADVISORY, SCORE_NAMES, Task

REPO = Path(__file__).resolve().parents[2]

CLASS_BLIND = "class-blind"
CLASS_AWARE = "class-aware"
MODES = (CLASS_BLIND, CLASS_AWARE)
NO_VERIFIER_SUFFIX = "+no_verifier"
#: The class-blind system spec (categories only; see agents/generic.md).
GENERIC_SPEC = "agents/generic.md"

#: Section headings whose bodies name the planted bug or the eval (dropped up to the next `## `).
LEAK_HEADINGS: Tuple[str, ...] = ("## The miss", "## Acceptance")
#: Any line mentioning the detector corpus is dropped as well.
LEAK_LINE_MARKERS: Tuple[str, ...] = ("evals/cases",)

_FRONT_MATTER = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.S)


@dataclass(frozen=True)
class Condition:
    """One prompt condition. `mode` picks the system/user texts; `verifier` is whether
    claim fidelity gates `passed` (False = the no-verifier ablation)."""
    mode: str = CLASS_AWARE
    verifier: bool = True

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"Condition.mode must be one of {MODES}, got {self.mode!r}")

    @property
    def name(self) -> str:
        return self.mode if self.verifier else self.mode + NO_VERIFIER_SUFFIX

    @property
    def passed_requires(self) -> Tuple[str, ...]:
        if self.verifier:
            return tuple(SCORE_NAMES)
        return tuple(n for n in SCORE_NAMES if n != "claim_fidelity")

    @staticmethod
    def parse(name: str) -> "Condition":
        """`class-blind` | `class-aware` | `<mode>+no_verifier` (the --condition / --ak value)."""
        text = (name or "").strip()
        verifier = True
        if text.endswith(NO_VERIFIER_SUFFIX):
            verifier = False
            text = text[: -len(NO_VERIFIER_SUFFIX)]
        if text not in MODES:
            raise ValueError(f"unknown condition {name!r}; expected one of "
                             f"{[m for m in MODES] + [m + NO_VERIFIER_SUFFIX for m in MODES]}")
        return Condition(mode=text, verifier=verifier)


def agent_body(path: Path) -> str:
    """The agents/<name>.md body with its YAML front matter stripped (moved from runner)."""
    return _FRONT_MATTER.sub("", Path(path).read_text(encoding="utf-8"), count=1).lstrip("\n")


def strip_leakage(body: str) -> str:
    """Drop every LEAK_HEADINGS section (heading through the line before the next `## `) and
    every line mentioning a LEAK_LINE_MARKERS string; collapse the blank lines left behind."""
    out = []
    skipping = False
    for line in body.splitlines():
        if line.startswith("## "):
            skipping = line.startswith(LEAK_HEADINGS)
            if skipping:
                continue
        if skipping:
            continue
        if any(marker in line for marker in LEAK_LINE_MARKERS):
            continue
        out.append(line)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip("\n")
    return text + "\n" if text else ""


def system_body(task: Task, cond: Condition, *, repo_root: Path = REPO) -> str:
    """class-blind: the generic spec; class-aware: the task's spec. Both leakage-stripped."""
    spec = GENERIC_SPEC if cond.mode == CLASS_BLIND else task.agent
    return strip_leakage(agent_body(Path(repo_root) / spec))


_REPORT_SCHEMA = ("schema: agent, property, repo, commit, findings[{id,file,line,evidence,status}], "
                  "claims[{statement,oracle,evidence}]")


def user_text(task: Task, cond: Condition, *, workdir: str) -> str:
    """The first user message. class-blind names neither the property nor the description
    (nor the task id, which encodes the property); class-aware names the property only and
    never an advisory task's description."""
    if cond.mode == CLASS_BLIND:
        return (
            f"Repository: the working tree at {workdir} (the only writable location); "
            f"commit {task.commit or 'HEAD'}.\n\n"
            f"Review this repository for security vulnerabilities. Fix what you find with minimal, "
            f"targeted edits; do not refactor unrelated code; do not add or modify files under tests/ "
            f"except to add a test that pins a fix. Use only the tools provided; run run_tests "
            f"after editing. Finish by calling write_report with the security-report JSON ({_REPORT_SCHEMA}); "
            f"`property` is P<n> for the n-th category of the system prompt your main finding belongs to "
            f"(P0 for none). Use `{workdir}` as `repo` and the current HEAD as `commit`. Oracles must be "
            f"commands runnable from the repo root that exit 0 iff the claim holds "
            f"(e.g. `python -m pytest tests -q`). Keep every description categorical. "
            f"Tool paths are relative to the repo root."
        )
    goal = ""
    if task.kind != KIND_ADVISORY and task.description:
        goal = f"Goal: {task.description}\n"
    return (
        f"Repository: {task.repo} (commit {task.commit})\n"
        f"Property: {task.property}\n"
        f"{goal}\n"
        f"Find and fix every violation of property {task.property} in the repository at {workdir} "
        f"(the only writable location), using only the tools provided; run run_tests after editing; "
        f"finish by calling write_report with the security-report JSON ({_REPORT_SCHEMA}). "
        f"Oracles must be commands runnable from the repo root (e.g. `python -m pytest tests -q`). "
        f"Tool paths are relative to the repo root."
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def prompt_hashes(task: Task, cond: Condition, *, workdir: str = "/app", repo_root: Path = REPO) -> Dict[str, str]:
    """{"system": sha256, "user": sha256} of the exact texts sent under `cond` for THIS task.
    The user text embeds the repo name and commit, so these differ per task; the registry
    pins `template_hashes` instead (integration fix, CONTRACTS.md A8)."""
    return {"system": _sha256(system_body(task, cond, repo_root=repo_root)),
            "user": _sha256(user_text(task, cond, workdir=workdir))}


#: The placeholder task the registry's `prompt_hashes` are computed from: every per-task value
#: (repo, commit, description, id) is a fixed token, so the hash covers the TEMPLATE only.
TEMPLATE_TASK = Task(task_id="<task_id>", eval_id="security.calib.egress.v1", repo="<repo>",
                     repo_url="<repo_url>", commit="<commit>", property="P4", description="<description>",
                     file="", find="", replace="", hidden_test="python -m pytest tests -q",
                     suite_test="python -m pytest tests -q", container_test=["python", "-m", "pytest", "tests", "-q"],
                     pythonpath=[], agent="agents/egress.md", canary="", source="advisory", kind=KIND_ADVISORY)


def template_hashes(cond: Condition, *, workdir: str = "/app", repo_root: Path = REPO) -> Dict[str, str]:
    """`prompt_hashes` of `TEMPLATE_TASK`: task-independent, so the registry can pin it and a run
    can detect prompt drift by recomputing it."""
    return prompt_hashes(TEMPLATE_TASK, cond, workdir=workdir, repo_root=repo_root)
