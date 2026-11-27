"""evals/calib/split.py: seeded, project-grouped, stratified assignment on a 40-task fixture;
the sa-dirtree-sha256-v1 hash and the seal; relative symlinks and tomllib-parsable manifests;
contamination bins. Fixture tasks name example.invalid projects. No model, no docker, no harbor."""
from __future__ import annotations

import json
import os
import tomllib
from collections import Counter
from pathlib import Path
from typing import Dict, List

import pytest

from evals.agent.types import SPLITS, Task
from evals.calib import split as sp

SUBS = ("redirect", "rebinding", "off_list", "scheme")
LIBS = ("requests", "httpx", "urllib")


def _task(tid: str, project: str, sub: str, lib: str, *, negative: bool = False, date: str = "2025-03-14") -> Task:
    return Task(task_id=tid, eval_id="security.calib.egress.v1", repo=tid, repo_url=f"https://example.invalid/{project}.git",
                commit="a" * 40, property="P4", description="categorical", file="pkg/f.py", find="", replace="",
                hidden_test="python -m pytest tests -q", suite_test="python -m pytest tests -q",
                container_test=["python", "-m", "pytest", "tests", "-q"], pythonpath=[], agent="agents/egress.md",
                canary="c", source="advisory", kind="advisory", is_negative=negative, project=project,
                sub_scenario=sub, library=lib, disclosure_date=date, scope_rule="reachable-from-fix")


def fixture_tasks() -> List[Task]:
    """40 tasks: 36 positives in 14 projects (sizes 1-4) over 4x3 strata, 2 fixed-twin negatives
    (sharing a positive's project) and 2 clean negatives (their own projects)."""
    tasks: List[Task] = []
    sizes = [4, 4, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 1, 1]           # 36 positives
    i = 0
    for p, size in enumerate(sizes):
        for _ in range(size):
            tasks.append(_task(f"P4-ghsa-{i:04d}", f"org/proj{p:02d}", SUBS[i % 4], LIBS[(i // 4) % 3],
                               date=f"202{5 + (i % 2)}-{(i % 12) + 1:02d}-10"))
            i += 1
    tasks.append(_task("P4-neg-proj00-fixed", "org/proj00", "redirect", "requests", negative=True))
    tasks.append(_task("P4-neg-proj05-fixed", "org/proj05", "scheme", "httpx", negative=True))
    tasks.append(_task("P4-neg-cleana-clean", "org/cleana", "other", "urllib", negative=True))
    tasks.append(_task("P4-neg-cleanb-clean", "org/cleanb", "other", "requests", negative=True))
    assert len(tasks) == 40
    return tasks


# ----------------------------------------------------------------- assignment

def test_assign_is_deterministic_from_seed_and_covers_every_task():
    tasks = fixture_tasks()
    a1, a2 = sp.assign(tasks, seed=0), sp.assign(tasks, seed=0)
    assert a1 == a2 and set(a1) == {t.task_id for t in tasks}
    assert set(a1.values()) <= set(SPLITS)
    assert any(sp.assign(tasks, seed=s) != a1 for s in range(1, 6))   # the seed matters


def test_assign_never_straddles_a_project():
    tasks = fixture_tasks()
    for seed in range(8):
        a = sp.assign(tasks, seed=seed)
        by_project: Dict[str, set] = {}
        for t in tasks:
            by_project.setdefault(t.project, set()).add(a[t.task_id])
        assert all(len(v) == 1 for v in by_project.values()), by_project
        # the fixed twin follows its positive's project
        assert a["P4-neg-proj00-fixed"] == a["P4-ghsa-0000"]


def test_assign_respects_fractions_within_one_project():
    tasks = fixture_tasks()
    max_group = 4 + 1          # proj00 has 4 positives + its fixed twin
    for seed in range(8):
        c = Counter(sp.assign(tasks, seed=seed).values())
        for split, frac in zip(SPLITS, (0.5, 0.2, 0.3)):
            assert abs(c[split] - frac * 40) <= max_group, (seed, dict(c))
        assert sum(c.values()) == 40


def test_assign_spreads_strata_and_negatives():
    tasks = fixture_tasks()
    a = sp.assign(tasks, seed=3)
    neg_splits = {a[t.task_id] for t in tasks if t.is_negative}
    assert len(neg_splits) >= 2                                   # negatives are not all in one split
    big = Counter(sp.stratum(t) for t in tasks if not t.is_negative)
    for st, n in big.items():
        if n >= 6:
            assert len({a[t.task_id] for t in tasks if sp.stratum(t) == st}) >= 2, st
    assert sp.counts(tasks, a)["negatives"] == 4 and sum(sp.counts(tasks, a)[s] for s in SPLITS) == 40


def test_assign_edge_cases():
    assert sp.assign([], seed=0) == {}
    with pytest.raises(ValueError):
        sp.assign(fixture_tasks(), seed=0, fractions=(0.5, 0.5, 0.5))
    with pytest.raises(ValueError):
        sp.assign(fixture_tasks() + [fixture_tasks()[0]], seed=0)
    one = sp.assign([_task("x", "org/x", "redirect", "requests")], seed=0)
    assert one == {"x": "train"}


def test_check_balance_warns_past_the_project_cap():
    tasks = fixture_tasks()
    assert sp.check_balance(tasks) == []                           # 4/36 = 11% < 15%
    skewed = tasks + [_task(f"P4-ghsa-9{i:03d}", "org/proj00", "redirect", "requests") for i in range(6)]
    w = sp.check_balance(skewed)
    assert len(w) == 1 and "org/proj00" in w[0] and "10/42" in w[0]


# ----------------------------------------------------------------- hashes

def _task_dir(root: Path, tid: str, *, body: str = "x") -> Path:
    d = root / tid
    (d / "tests").mkdir(parents=True)
    (d / "task.toml").write_text(f'schema_version = "1.4"\n[task]\nname = "security-agents/{tid}"\n')
    (d / "instruction.md").write_text("Review this repository.\n")
    (d / "tests" / "hidden.patch").write_text(body)
    return d


def test_dir_hash_is_content_only_and_order_independent(tmp_path: Path):
    d = _task_dir(tmp_path / "a", "t1")
    h1 = sp.dir_hash(d)
    os.utime(d / "task.toml", (0, 0))
    assert sp.dir_hash(d) == h1 and len(h1) == 64
    d2 = _task_dir(tmp_path / "b", "t1")
    assert sp.dir_hash(d2) == h1                                   # same content elsewhere
    (d2 / "tests" / "hidden.patch").write_text("y")
    assert sp.dir_hash(d2) != h1
    (tmp_path / "empty").mkdir()
    assert sp.dir_hash(tmp_path / "empty") == sp.dir_hash(tmp_path / "empty")
    with pytest.raises(FileNotFoundError):
        sp.dir_hash(tmp_path / "missing")


def test_seal_hash_is_order_independent():
    pairs = [("t2", "b" * 64), ("t1", "a" * 64)]
    assert sp.seal_hash(pairs) == sp.seal_hash(list(reversed(pairs)))
    assert sp.seal_hash(pairs) != sp.seal_hash([("t1", "a" * 64)])


# ----------------------------------------------------------------- symlinks, manifests, seal

def _class_dir(tmp_path: Path, tasks: List[Task]) -> Path:
    class_dir = tmp_path / "egress"
    for t in tasks:
        _task_dir(class_dir / "tasks", t.task_id)
    return class_dir


def test_write_splits_relative_symlinks_and_tomllib_manifests(tmp_path: Path):
    tasks = fixture_tasks()
    class_dir = _class_dir(tmp_path, tasks)
    a = sp.assign(tasks, seed=0)
    out = sp.write_splits(tasks, a, splits_dir=class_dir / "splits", class_dir=class_dir, seed=0)
    assert set(out) == set(SPLITS)
    for split, d in out.items():
        links = sorted(p for p in d.iterdir() if p.is_symlink())
        assert [p.name for p in links] == sorted(t for t, s in a.items() if s == split)
        for link in links:
            target = os.readlink(link)
            assert not os.path.isabs(target) and target == f"../../tasks/{link.name}"
            assert (link / "task.toml").is_file()                   # resolves through the relative link
        text = (class_dir / "splits" / f"{split}.dataset.toml").read_text()
        doc = tomllib.loads(text)
        assert doc["dataset"]["name"] == f"security-agents/calib-egress-{split}"
        assert doc["metadata"]["digest_algorithm"] == "sa-dirtree-sha256-v1" and doc["metadata"]["seed"] == 0
        assert doc["metadata"]["counts"]["tasks"] == len(links)
        assert {t["name"] for t in doc["tasks"]} == {f"security-agents/{p.name}" for p in links}
        for t in doc["tasks"]:
            tid = t["name"].split("/", 1)[1]
            assert t["digest"] == "sha256:" + sp.dir_hash(class_dir / "tasks" / tid)
    # a second write with a different assignment removes stale links
    a2 = sp.assign(tasks, seed=1)
    sp.write_splits(tasks, a2, splits_dir=class_dir / "splits", class_dir=class_dir, seed=1)
    for split in SPLITS:
        names = {p.name for p in (class_dir / "splits" / split).iterdir() if p.is_symlink()}
        assert names == {t for t, s in a2.items() if s == split}


def test_manifest_toml_needs_a_hash_per_task():
    with pytest.raises(ValueError):
        sp.manifest_toml("train", [_task("x", "org/x", "redirect", "requests")], {})
    with pytest.raises(ValueError):
        sp.manifest_toml("dev", [], {})


def test_check_seal_detects_an_edited_test_task(tmp_path: Path):
    tasks = fixture_tasks()
    class_dir = _class_dir(tmp_path, tasks)
    a = sp.assign(tasks, seed=0)
    tasks_dir = class_dir / "tasks"
    test_ids = sorted(t for t, s in a.items() if s == "test")
    seal = sp.seal_hash([(t, sp.dir_hash(tasks_dir / t)) for t in test_ids])
    tasks_file = class_dir / "tasks.jsonl"
    tasks_file.write_text("".join(json.dumps({**t.to_record(), "split": a[t.task_id]}) + "\n" for t in tasks))
    registry = {"tasks": str(tasks_file), "splits": {"test_hash": seal}}

    ok, msg = sp.check_seal(registry, tasks_dir)
    assert ok and "intact" in msg
    ok, msg = sp.check_seal(registry, tasks_dir, assignment=a)
    assert ok
    # editing a TRAIN task does not break the seal; editing a TEST task does
    train_id = next(t for t, s in a.items() if s == "train")
    (tasks_dir / train_id / "instruction.md").write_text("changed\n")
    assert sp.check_seal(registry, tasks_dir)[0]
    (tasks_dir / test_ids[0] / "tests" / "hidden.patch").write_text("edited\n")
    ok, msg = sp.check_seal(registry, tasks_dir)
    assert not ok and "seal broken" in msg
    # unsealed and missing cases
    assert not sp.check_seal({"tasks": str(tasks_file), "splits": {"test_hash": ""}}, tasks_dir)[0]
    assert "does not exist" in sp.check_seal({"tasks": str(tmp_path / "nope.jsonl"), "splits": {"test_hash": seal}}, tasks_dir)[1]


# ----------------------------------------------------------------- contamination

def test_contamination_bin_month_granularity():
    cut = {"claude-fable-5-1": "2026-06", "claude-sonnet-5-5": "unknown"}
    assert sp.contamination_bin("2026-06-30", "claude-fable-5-1", cut) == "pre"
    assert sp.contamination_bin("2026-06-01", "claude-fable-5-1", cut) == "pre"
    assert sp.contamination_bin("2026-07-01", "claude-fable-5-1", cut) == "post"
    assert sp.contamination_bin("2019-01-01", "claude-fable-5-1", cut) == "pre"
    assert sp.contamination_bin("2026-01-01", "claude-sonnet-5-5", cut) == "unknown"
    assert sp.contamination_bin("2026-01-01", "no-such-model", cut) == "unknown"
    assert sp.contamination_bin("", "claude-fable-5-1", cut) == "unknown"


def test_load_cutoffs_reads_the_committed_file():
    cut = sp.load_cutoffs()
    assert cut["claude-fable-5-1"] == "2026-06" and cut["claude-sonnet-5-5"] == "unknown"
    assert all(isinstance(v, str) for v in cut.values())
