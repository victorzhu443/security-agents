"""Splits, seal and contamination bins for the calibration tasks (Phase 1, W-D).

    stratum(task)                 "sub_scenario|library" — the stratification key
    assign(tasks, seed=...)       task_id -> train | validation | test; grouped by `project`
                                  (a project never straddles splits), stratified, seeded
    check_balance(tasks)          warnings: a project above 15 % of the positives (A3 cap)
    dir_hash(task_dir)            "sa-dirtree-sha256-v1" content hash of one Harbor task dir
    seal_hash(pairs)              the registry's `splits.test_hash` over (task_id, dir_hash)
    write_splits(...)             splits/<split>/<task_id> relative symlinks + <split>.dataset.toml
    manifest_toml(...)            the Harbor-shaped dataset manifest (a sealed record, not what
                                  `harbor run -p` reads — see CONTRACTS.md "Harbor facts")
    check_seal(registry, ...)     recompute test_hash and compare with the registry entry
    load_cutoffs() / contamination_bin(...)   pre | post | unknown at month granularity

Why the splits are directories of symlinks: `harbor run -p <dir>` treats every valid task
subdirectory of <dir> as the dataset (a `dataset.toml` given to `-p` is a *package* manifest
resolved through a registry, not a list of local paths). `splits/<split>/` is therefore what
`harbor run` reads, and `<split>.dataset.toml` is the publishable record of the same set with
our own digest algorithm (`[metadata] digest_algorithm`), so nobody mistakes it for a Hub digest.

Assignment algorithm (deterministic from `seed`):
  1. group tasks by `project` (a task without one is its own group); a group's stratum is the
     most common stratum of its positive tasks (ties: lexicographic), or "negative|<stratum>"
     when it holds negatives only, so negatives are spread over the splits the same way;
  2. shuffle the sorted group keys with `random.Random(seed)`;
  3. for each group in that order, pick the split with the largest remaining deficit
     (target - assigned, in tasks) summed over the stratum and the whole set; ties in SPLITS
     order. The global term keeps the fractions within one project of the targets; the stratum
     term keeps every stratum represented in every split where its size allows.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import yaml

from ..agent.types import SPLITS, Task
from . import CLASS_DIR, CLASS_NAME, CUTOFFS_FILE, REPO, SPLITS_DIR, TASK_ORG, TASKS_DIR

DIGEST_ALGORITHM = "sa-dirtree-sha256-v1"
DEFAULT_FRACTIONS: Tuple[float, float, float] = (0.5, 0.2, 0.3)
#: A3: co-selection caps any project at this share of the positives; `assign` warns past it.
PROJECT_CAP = 0.15
_MONTH_RE = re.compile(r"^(\d{4})-(\d{2})")


# ----------------------------------------------------------------- strata and assignment

def stratum(task: Task) -> str:
    return f"{task.sub_scenario}|{task.library}"


def _group_key(task: Task) -> str:
    return task.project or task.task_id


def _group_stratum(tasks: Sequence[Task]) -> str:
    positives = [t for t in tasks if not t.is_negative]
    pool = positives or list(tasks)
    counts = Counter(stratum(t) for t in pool)
    best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return best if positives else f"negative|{best}"


def check_balance(tasks: Sequence[Task], *, cap: float = PROJECT_CAP) -> List[str]:
    """Warnings for projects holding more than `cap` of the positive tasks (A3 monoculture
    cap). Returns sentences; empty when balanced."""
    positives = [t for t in tasks if not t.is_negative]
    if not positives:
        return []
    counts = Counter(_group_key(t) for t in positives)
    out = []
    for proj, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        share = n / len(positives)
        if share > cap:
            out.append(f"project {proj} holds {n}/{len(positives)} positives ({share:.0%}), "
                       f"above the {cap:.0%} cap; it cannot straddle splits, so one split carries it all")
    return out


def assign(tasks: Sequence[Task], *, seed: int,
           fractions: Tuple[float, float, float] = DEFAULT_FRACTIONS) -> Dict[str, str]:
    """task_id -> split. See the module docstring for the algorithm."""
    if len(fractions) != len(SPLITS) or abs(sum(fractions) - 1.0) > 1e-9 or min(fractions) < 0:
        raise ValueError(f"fractions must be {len(SPLITS)} non-negative numbers summing to 1, got {fractions}")
    ids = [t.task_id for t in tasks]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate task ids")
    groups: Dict[str, List[Task]] = defaultdict(list)
    for t in tasks:
        groups[_group_key(t)].append(t)
    if not groups:
        return {}
    group_stratum = {g: _group_stratum(ts) for g, ts in groups.items()}
    stratum_total: Dict[str, int] = Counter()
    for g, ts in groups.items():
        stratum_total[group_stratum[g]] += len(ts)
    total = len(tasks)
    assigned_global: Dict[str, int] = {s: 0 for s in SPLITS}
    assigned_stratum: Dict[str, Dict[str, int]] = {st: {s: 0 for s in SPLITS} for st in stratum_total}

    order = sorted(groups)
    random.Random(seed).shuffle(order)

    out: Dict[str, str] = {}
    for g in order:
        w = len(groups[g])
        st = group_stratum[g]
        best, best_score = None, None
        for s, f in zip(SPLITS, fractions):
            deficit = (f * total - assigned_global[s]) + (f * stratum_total[st] - assigned_stratum[st][s])
            if best_score is None or deficit > best_score + 1e-12:
                best, best_score = s, deficit
        assert best is not None
        assigned_global[best] += w
        assigned_stratum[st][best] += w
        for t in groups[g]:
            out[t.task_id] = best
    return out


def counts(tasks: Sequence[Task], assignment: Dict[str, str]) -> Dict[str, int]:
    """{train, validation, test, negatives} — the registry's `splits.counts`."""
    c = {s: 0 for s in SPLITS}
    c["negatives"] = 0
    for t in tasks:
        s = assignment.get(t.task_id)
        if s in c:
            c[s] += 1
        if t.is_negative:
            c["negatives"] += 1
    return c


# ----------------------------------------------------------------- hashes

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def dir_hash(task_dir: Path) -> str:
    """`sa-dirtree-sha256-v1`: sha256 over the sorted lines "relpath\\0sha256(bytes)\\n" of
    every regular file under `task_dir` (relpath POSIX-style, relative to task_dir). File
    modes and timestamps are ignored; an empty directory hashes the empty string."""
    task_dir = Path(task_dir)
    if not task_dir.is_dir():
        raise FileNotFoundError(f"task dir {task_dir} does not exist")
    lines = []
    for p in sorted(task_dir.rglob("*")):
        if p.is_file():
            rel = p.relative_to(task_dir).as_posix()
            lines.append(f"{rel}\0{_sha256_file(p)}\n")
    lines.sort()
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def seal_hash(test_tasks: Sequence[Tuple[str, str]]) -> str:
    """sha256 over the sorted lines "task_id:dir_hash\\n" — the registry's `splits.test_hash`."""
    lines = sorted(f"{tid}:{h}\n" for tid, h in test_tasks)
    return hashlib.sha256("".join(lines).encode()).hexdigest()


# ----------------------------------------------------------------- manifests and symlinks

def _toml_str(s: str) -> str:
    return json.dumps(str(s), ensure_ascii=True)


def manifest_toml(split: str, tasks: Sequence[Task], hashes: Dict[str, str], *,
                  seed: Optional[int] = None, version: str = "1") -> str:
    """The Harbor-shaped dataset manifest for one split. `hashes` maps task_id -> dir_hash.
    Parses with tomllib; `[metadata] digest_algorithm` names our algorithm so the digests are
    never mistaken for Hub (dirhash) digests."""
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}")
    ts = sorted(tasks, key=lambda t: t.task_id)
    negatives = sum(1 for t in ts if t.is_negative)
    L = [f"# security-agents calib-{CLASS_NAME} {split} split — sealed record written by `python -m evals calib-split`.",
         "# `harbor run -p` reads the symlink directory next to this file, not this manifest.",
         'schema_version = "1.0"', "",
         "[dataset]",
         f"name = {_toml_str(f'{TASK_ORG}/calib-{CLASS_NAME}-{split}')}",
         f"version = {_toml_str(version)}",
         f"description = {_toml_str(f'{split} split of the {CLASS_NAME} calibration tasks (advisory-derived, see evals/calib/CONTRACTS.md)')}",
         'keywords = ["security"]', "",
         "[metadata]",
         f"digest_algorithm = {_toml_str(DIGEST_ALGORITHM)}",
         f"split = {_toml_str(split)}",
         f"seed = {int(seed) if seed is not None else -1}",
         f"counts = {{ tasks = {len(ts)}, positives = {len(ts) - negatives}, negatives = {negatives} }}", ""]
    for t in ts:
        h = hashes.get(t.task_id)
        if not h or not re.fullmatch(r"[0-9a-f]{64}", h):
            raise ValueError(f"no sha256 dir_hash for task {t.task_id}")
        L += ["[[tasks]]", f"name = {_toml_str(f'{TASK_ORG}/{t.task_id}')}", f'digest = "sha256:{h}"', ""]
    return "\n".join(L)


def manifest_path(split: str, splits_dir: Path = SPLITS_DIR) -> Path:
    return Path(splits_dir) / f"{split}.dataset.toml"


def write_splits(tasks: Sequence[Task], assignment: Dict[str, str], *, splits_dir: Path = SPLITS_DIR,
                 class_dir: Path = CLASS_DIR, seed: Optional[int] = None) -> Dict[str, Path]:
    """Write `splits/<split>/<task_id>` RELATIVE symlinks to `../../tasks/<task_id>` and one
    `<split>.dataset.toml` per split. Stale symlinks from a previous assignment are removed.
    Returns {split: split_dir}. Every task dir must exist (its hash goes in the manifest)."""
    splits_dir, class_dir = Path(splits_dir), Path(class_dir)
    tasks_dir = class_dir / "tasks"
    by_split: Dict[str, List[Task]] = {s: [] for s in SPLITS}
    for t in tasks:
        s = assignment.get(t.task_id)
        if s is None:
            raise ValueError(f"task {t.task_id} has no split assignment")
        if s not in by_split:
            raise ValueError(f"task {t.task_id}: unknown split {s!r}")
        by_split[s].append(t)
    hashes = {t.task_id: dir_hash(tasks_dir / t.task_id) for t in tasks}
    out: Dict[str, Path] = {}
    for s, ts in by_split.items():
        d = splits_dir / s
        d.mkdir(parents=True, exist_ok=True)
        for old in d.iterdir():
            if old.is_symlink():
                old.unlink()
        for t in ts:
            link = d / t.task_id
            target = os.path.relpath(tasks_dir / t.task_id, d)
            os.symlink(target, link)
        manifest_path(s, splits_dir).write_text(manifest_toml(s, ts, hashes, seed=seed))
        out[s] = d
    return out


# ----------------------------------------------------------------- the seal

def load_tasks_jsonl(path: Path) -> List[Task]:
    out = []
    for line in Path(path).read_text().splitlines():
        if line.strip():
            out.append(Task(**json.loads(line)))
    return out


def _registry_path(value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else REPO / p


def check_seal(registry: Dict, tasks_dir: Path = TASKS_DIR,
               assignment: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    """Recompute `splits.test_hash` over the current test task dirs and compare. The test ids
    come from `assignment` when given, else from the `split` field of the registry's tasks.jsonl.
    -> (ok, message)."""
    want = str((registry.get("splits") or {}).get("test_hash") or "")
    if assignment is not None:
        test_ids = sorted(tid for tid, s in assignment.items() if s == "test")
    else:
        tasks_file = _registry_path(str(registry.get("tasks") or ""))
        if not tasks_file.is_file():
            return False, f"cannot check the seal: {tasks_file} does not exist"
        test_ids = sorted(t.task_id for t in load_tasks_jsonl(tasks_file) if t.split == "test")
    if not want:
        return False, f"the test split is not sealed yet (test_hash empty; {len(test_ids)} test task(s))"
    pairs = []
    for tid in test_ids:
        d = Path(tasks_dir) / tid
        if not d.is_dir():
            return False, f"seal broken: test task dir {d} is missing"
        pairs.append((tid, dir_hash(d)))
    got = seal_hash(pairs)
    if got != want:
        return False, f"seal broken: test_hash {want[:12]}… recorded, {got[:12]}… recomputed over {len(pairs)} task(s)"
    return True, f"seal intact: {want[:12]}… over {len(pairs)} test task(s)"


# ----------------------------------------------------------------- contamination

def load_cutoffs(path: Path = CUTOFFS_FILE) -> Dict[str, str]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return {str(k): str(v) for k, v in (data.get("cutoffs") or {}).items()}


def contamination_bin(disclosure_date: str, model: str, cutoffs: Dict[str, str]) -> str:
    """pre | post | unknown at month granularity: a disclosure on or before the last day of
    the model's cutoff month is `pre` (the fix may be in its training data)."""
    cutoff = str(cutoffs.get(model, "unknown"))
    m_cut = _MONTH_RE.match(cutoff)
    m_dis = _MONTH_RE.match(str(disclosure_date or ""))
    if not m_cut or not m_dis:
        return "unknown"
    return "pre" if (int(m_dis.group(1)), int(m_dis.group(2))) <= (int(m_cut.group(1)), int(m_cut.group(2))) else "post"
