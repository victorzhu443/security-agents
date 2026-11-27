"""evals/calib/runner.py, sast.py, the registry entry, baselines.yaml, the calib card and the
agent gate: harbor_argv shape, parse_job on a hand-written JobResult fixture (+ RewardKit
reward-details), the Layer-6 summary, the refusals, dry runs that write nothing, the validity
rc rules, the SAST adapters, decide_agent. No model, no docker, no harbor, no network."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

import pytest
import yaml

from evals import cards, gate
from evals.__main__ import main as cli
from evals.agent.types import SCORE_NAMES, Task
from evals.calib import EVAL_ID, REGISTRY_FILE, REPO, sast
from evals.calib import runner as R
from evals.metrics import wilson_ci
from evals.registry import canary as registry_canary

CANARY = registry_canary()


# ----------------------------------------------------------------- fixtures

def _task(tid: str, *, negative: bool = False, split: str = "train", sub: str = "redirect", lib: str = "requests",
          date: str = "2025-03-14", project: str = "org/proj") -> Task:
    return Task(task_id=tid, eval_id=EVAL_ID, repo=tid, repo_url=f"https://example.invalid/{project}.git", commit="a" * 40,
                property="P4", description="categorical", file="pkg/f.py", find="", replace="",
                hidden_test="python -m pytest tests -q", suite_test="python -m pytest tests -q",
                container_test=["python", "-m", "pytest", "tests", "-q"], pythonpath=[], agent="agents/egress.md",
                canary=CANARY, source="advisory", kind="advisory", is_negative=negative, project=project,
                sub_scenario=sub, library=lib, disclosure_date=date, split=split, scope_rule="reachable-from-fix",
                task_dir=f"evals/calib/egress/tasks/{tid}")


TASKS = {t.task_id: t for t in [
    _task("P4-ghsa-aaaa", date="2025-03-14", project="org/a"),                 # pre (fable cutoff 2026-06)
    _task("P4-ghsa-bbbb", date="2026-09-01", project="org/b", lib="httpx"),    # post
    _task("P4-ghsa-cccc", date="2026-01-01", project="org/c", split="validation"),
    _task("P4-neg-a-fixed", negative=True, date="2025-03-14", project="org/a"),
    _task("P4-neg-z-clean", negative=True, date="2026-09-01", project="org/z", split="validation", sub="other"),
]}


def _details(hidden: float, hidden_rc: int, suite: float = 1.0, *, recall: float = 1.0, fp: float = 1.0,
             recall_reason: str = "", unscored: str = "") -> Dict:
    """A plausible RewardKit reward-details.json (its schema is only partly documented; the
    parser is tolerant: criteria are objects with `score` and optional `reasoning`)."""
    return {"reward": 1.0, "dimensions": [
        {"name": "recall", "score": recall, "criteria": [
            {"name": "finding_in_fix_hunk", "score": recall, "weight": 1.0, "reasoning": recall_reason}]},
        {"name": "fix", "score": min(hidden, suite), "criteria": [
            {"name": "hidden_test_passes", "score": hidden, "weight": 1.0,
             "reasoning": unscored or f"rc={hidden_rc}"},
            {"name": "suite_passes", "score": suite, "weight": 1.0, "reasoning": f"rc={0 if suite >= 1 else 1}"}]},
        {"name": "claim_fidelity", "score": 1.0, "criteria": [{"name": "claims_verified", "score": 1.0}]},
        {"name": "scope_safety", "score": 1.0, "criteria": [{"name": "diff_in_scope", "score": 1.0}]},
        {"name": "fp", "score": fp, "criteria": [{"name": "no_class_finding", "score": fp, "reasoning": ""}]},
    ]}


def _trial(task: str, name: str, rewards, *, cost=0.01, exc=None, started="2026-11-27T10:00:00Z",
           finished="2026-11-27T10:05:30Z") -> Dict:
    """One TrialResult shaped like harbor.models.trial.result.TrialResult (fields from the contract)."""
    return {"schema_version": 1, "id": "00000000-0000-0000-0000-000000000001", "task_name": task, "trial_name": name,
            "trial_uri": f"file:///jobs/x/{name}", "task_id": {"path": f"/tasks/{task}"}, "source": "train",
            "task_checksum": "deadbeef", "config": {"task": {"path": f"/tasks/{task}"}},
            "agent_info": {"name": "security-agents", "version": "0.1.1", "model_info": {"name": "claude-sonnet-5-5", "provider": "anthropic"}},
            "agent_result": {"n_input_tokens": 1000, "n_cache_tokens": 200, "n_output_tokens": 300, "cost_usd": cost,
                             "metadata": {"condition": "class-blind"}},
            "verifier_result": {"rewards": rewards} if rewards is not None else None,
            "verifier_environment_mode": "separate",
            "exception_info": exc, "started_at": started, "finished_at": finished}


def write_job(job_dir: Path) -> Path:
    """A hand-written Harbor job dir: result.json (JobResult) + per-trial reward-details.json."""
    ok = {"reward": 1.0, "recall": 1.0, "fix": 1.0, "claim_fidelity": 1.0, "scope_safety": 1.0, "fp": 1.0}
    miss = {"reward": 0.0, "recall": 0.0, "fix": 0.0, "claim_fidelity": 1.0, "scope_safety": 1.0, "fp": 1.0}
    neg_fp = {"reward": 0.0, "recall": 1.0, "fix": 1.0, "claim_fidelity": 1.0, "scope_safety": 1.0, "fp": 0.0}
    trials = [
        _trial("P4-ghsa-aaaa", "P4-ghsa-aaaa__1", ok), _trial("P4-ghsa-aaaa", "P4-ghsa-aaaa__2", ok),
        _trial("P4-ghsa-bbbb", "P4-ghsa-bbbb__1", ok), _trial("P4-ghsa-bbbb", "P4-ghsa-bbbb__2", miss),
        _trial("P4-ghsa-cccc", "P4-ghsa-cccc__1", miss),
        _trial("P4-ghsa-cccc", "P4-ghsa-cccc__2", None, cost=0.0,
               exc={"exception_type": "AgentTimeoutError", "exception_message": "agent exceeded 1800s",
                    "exception_traceback": "...", "occurred_at": "2026-11-27T10:30:00Z"}),
        _trial("P4-neg-a-fixed", "P4-neg-a-fixed__1", ok), _trial("P4-neg-a-fixed", "P4-neg-a-fixed__2", ok),
        _trial("P4-neg-z-clean", "P4-neg-z-clean__1", neg_fp), _trial("P4-neg-z-clean", "P4-neg-z-clean__2", ok),
    ]
    details = {
        "P4-ghsa-aaaa__1": _details(1.0, 0), "P4-ghsa-aaaa__2": _details(1.0, 0),
        "P4-ghsa-bbbb__1": _details(1.0, 0), "P4-ghsa-bbbb__2": _details(0.0, 1, recall=0.0),
        "P4-ghsa-cccc__1": _details(0.0, 1, recall=0.0),
        "P4-neg-a-fixed__1": _details(1.0, 0, recall_reason="not-applicable"),
        "P4-neg-a-fixed__2": _details(1.0, 0, recall_reason="not-applicable"),
        "P4-neg-z-clean__1": _details(1.0, 0, fp=0.0, recall_reason="not-applicable"),
        "P4-neg-z-clean__2": _details(1.0, 0, recall_reason="not-applicable"),
    }
    if job_dir.is_dir():
        return job_dir
    job_dir.mkdir(parents=True)
    (job_dir / "result.json").write_text(json.dumps({
        "schema_version": 1, "id": "11111111-1111-1111-1111-111111111111", "started_at": "2026-11-27T10:00:00Z",
        "finished_at": "2026-11-27T11:00:00Z", "n_total_trials": len(trials),
        "stats": {"n_completed_trials": len(trials), "n_errored_trials": 1, "cost_usd": 0.09},
        "trial_results": trials}))
    for name, d in details.items():
        (job_dir / name / "verifier").mkdir(parents=True)
        (job_dir / name / "verifier" / "reward-details.json").write_text(json.dumps(d))
    (job_dir / "P4-ghsa-aaaa__1" / "artifacts").mkdir()
    (job_dir / "P4-ghsa-aaaa__1" / "artifacts" / "report.json").write_text(json.dumps(
        {"agent": "x", "property": "P4", "repo": "/app", "commit": "a" * 40, "claims": [],
         "findings": [{"id": "f1", "file": "pkg/f.py", "line": 10, "evidence": "e", "status": "fixed"}]}))
    return job_dir


# ----------------------------------------------------------------- harbor_argv

def test_harbor_argv_shape():
    argv = R.harbor_argv(dataset_dir=Path("/d/splits/train"), agent="evals.agent.harbor_agent:SecurityAgent",
                         model="claude-sonnet-5-5", trials=3, concurrency=2, jobs_dir=Path("/o/jobs"), job_name="j",
                         agent_kwargs={"condition": "class-blind", "budget_usd": "0.5"}, extra=["-e", "docker", "-i", "t1"])
    assert argv == ["harbor", "run", "-p", "/d/splits/train", "-a", "evals.agent.harbor_agent:SecurityAgent",
                    "-m", "claude-sonnet-5-5", "-k", "3", "-n", "2", "-o", "/o/jobs", "--job-name", "j",
                    "--ak", "budget_usd=0.5", "--ak", "condition=class-blind", "-e", "docker", "-i", "t1"]
    no_model = R.harbor_argv(dataset_dir=Path("t"), agent="nop", model=None, trials=1, concurrency=4,
                             jobs_dir=Path("j"), job_name="n", agent_kwargs={})
    assert "-m" not in no_model and "--ak" not in no_model


# ----------------------------------------------------------------- parse_job

def test_parse_job_on_a_jobresult_fixture(tmp_path: Path):
    recs = R.parse_job(write_job(tmp_path / "job"), metadata={"backend": "docker"})
    assert len(recs) == 10
    by = {(r["task_id"], r["trial"]): r for r in recs}
    r = by[("P4-ghsa-aaaa", 1)]
    assert r["rewards"]["reward"] == 1.0 and r["value"] is r["rewards"]
    assert r["tokens"] == {"input": 1000, "cache": 200, "output": 300} and r["cost_usd"] == 0.01
    assert r["elapsed_s"] == 330.0 and r["error"] == "" and r["agent"] == "security-agents"
    assert r["agent_version"] == "0.1.1" and r["model"] == "claude-sonnet-5-5"
    assert r["details"]["hidden_test_passes"] == {"score": 1.0, "reasoning": "rc=0", "rc": 0, "error": None}
    assert r["metadata"]["rc"] == {"hidden_test_passes": 0, "suite_passes": 0} and r["metadata"]["backend"] == "docker"
    assert r["answer"] == {"findings": 1, "files": ["pkg/f.py"]}
    assert "hidden_test_passes: rc=0" in r["explanation"]
    assert r["unscored"] is False and r["unscored_reason"] == ""
    bad = by[("P4-ghsa-cccc", 2)]
    assert bad["rewards"] is None and bad["error"].startswith("AgentTimeoutError:")
    assert bad["unscored"] is True and bad["unscored_reason"] == "verifier_timeout"
    assert by[("P4-ghsa-bbbb", 2)]["details"]["hidden_test_passes"]["rc"] == 1
    assert by[("P4-neg-a-fixed", 1)]["details"]["finding_in_fix_hunk"]["reasoning"] == "not-applicable"
    with pytest.raises(FileNotFoundError):
        R.parse_job(tmp_path / "nope")


def test_parse_reward_details_is_tolerant_of_shapes():
    nested = {"criteria": {"hidden_test_passes": {"score": 0, "reasoning": "unscored:verifier_timeout rc=124"},
                           "suite_passes": {"score": 1.0}}}
    d = R.parse_reward_details(nested)
    assert d["hidden_test_passes"]["rc"] == 124 and d["suite_passes"]["score"] == 1.0
    flat = [{"criterion": "no_class_finding", "score": 1, "reason": "no finding on fp_files"}]
    assert R.parse_reward_details(flat)["no_class_finding"]["reasoning"] == "no finding on fp_files"
    assert R.parse_reward_details({"score": True}) == {}            # booleans are not scores
    assert R.unscored_state("", {"reward": 1.0}, d) == (True, "verifier_timeout")
    assert R.unscored_state("", None, {}) == (True, "missing_rewards")
    assert R.unscored_state("DockerError", {"reward": 1.0}, {}) == (True, "sandbox_failure")
    assert R.unscored_state("", {"reward": 1.0}, {"x": {"score": 1.0, "reasoning": "ok"}}) == (False, "")


# ----------------------------------------------------------------- summary

def _summary(tmp_path: Path, **kw):
    recs = R.parse_job(write_job(tmp_path / "job"))
    registry = R.load_calib_registry()
    args = dict(tasks=TASKS, model="claude-fable-5-1", condition="class-blind", split="train",
                cutoffs={"claude-fable-5-1": "2026-06"}, trials=2, budget_usd=10.0, prompt_hashes={}, registry=registry)
    args.update(kw)
    return R.build_calib_summary(recs, **args), recs


def test_build_calib_summary_blocks_cis_fpr_bins_passk(tmp_path: Path):
    s, recs = _summary(tmp_path)
    o = s["overall"]
    assert o["n"] == 9 and o["n_unscored"] == 1 and o["unscored_reasons"] == {"verifier_timeout": 1}
    assert o["tasks"] == 5 and o["positive_tasks"] == 3 and o["negative_tasks"] == 2
    assert o["positives"] == 5 and o["negatives"] == 4                 # scored trials (cccc's 2nd is unscored)
    # recall over positives only: aaaa 1,1  bbbb 1,0  cccc 0 -> 3/5
    assert o["recall"] == 0.6 and o["recall_ci95"] == [round(x, 3) for x in wilson_ci(3, 5)]
    assert o["recall_stderr"] is not None and o["pass_rate_stderr"] is not None
    # fpr over negatives: one fp in 4 negative trials
    assert o["fp"] == 1 and o["fpr"] == 0.25 and len(o["fpr_ci95"]) == 2
    assert o["passed"] == 6 and o["pass_rate"] == round(6 / 9, 3)
    assert o["errors"] == 0 and o["hidden_patch_conflicts"] == 0
    assert set(o["pass_at_k"]) == {"1", "2"} and o["pass_pow_k"]["2"] is not None
    assert o["cost_usd_total"] == 0.09 and o["tokens"]["input"] == 9000
    # grouped blocks
    assert set(s["splits"]) == {"train", "validation"} and s["splits"]["train"]["tasks"] == 3
    assert set(s["contamination"]["bins"]) == {"pre", "post", "unknown"}
    assert s["contamination"]["bins"]["pre"]["tasks"] == 3 and s["contamination"]["bins"]["post"]["tasks"] == 2
    assert s["contamination"]["bins"]["unknown"]["n"] == 0 and s["contamination"]["cutoff"] == "2026-06"
    assert "redirect|requests" in s["strata"] and "redirect|httpx" in s["strata"] and "other|requests" in s["strata"]
    assert s["evals"] == {EVAL_ID: o}
    # tasks list for the gate
    by = {t["task_id"]: t for t in s["tasks"]}
    assert by["P4-ghsa-aaaa"]["passed"] is True and by["P4-ghsa-bbbb"]["passed"] is False
    assert by["P4-ghsa-cccc"]["trials"] == 1 and by["P4-ghsa-cccc"]["unscored"] == 1
    assert by["P4-neg-z-clean"]["passes"] == 1 and by["P4-neg-z-clean"]["is_negative"] is True
    assert "power" in s["power_note"] and s["budget"]["note"] == R.BUDGET_NOTE
    assert s["prompt_hashes"]["pinned"] is False and s["prompt_drift"] is False
    report = R.render_calib_report({**s, "run_id": "r"}, recs)
    assert "| metric | train | validation | test |" in report and "| metric | pre | post | unknown |" in report
    assert "FPR (negatives)" in report and "P4-ghsa-cccc" in report


def test_summary_prompt_drift_and_ablation_requires(tmp_path: Path):
    registry = R.load_calib_registry()
    pinned = {**registry, "prompt_hashes": {**registry["prompt_hashes"], "class-blind": {"system": "a" * 64, "user": "b" * 64}}}
    s, _ = _summary(tmp_path, registry=pinned, prompt_hashes={"system": "a" * 64, "user": "b" * 64})
    assert s["prompt_hashes"]["pinned"] and not s["prompt_drift"]
    s, _ = _summary(tmp_path, registry=pinned, prompt_hashes={"system": "a" * 64, "user": "c" * 64})
    assert s["prompt_drift"] is True
    # no_verifier: claim_fidelity no longer gates `passed`
    recs = R.parse_job(tmp_path / "job")
    for r in recs:
        if r["rewards"]:
            r["rewards"]["claim_fidelity"] = 0.0
    s_full = R.build_calib_summary(recs, tasks=TASKS, model="m", condition="class-blind", split="train", cutoffs={},
                                   trials=2, budget_usd=1.0, prompt_hashes={}, registry=registry)
    s_abl = R.build_calib_summary(recs, tasks=TASKS, model="m", condition="class-blind+no_verifier", split="train",
                                  cutoffs={}, trials=2, budget_usd=1.0, prompt_hashes={}, registry=registry,
                                  requires=R.condition_requires("no_verifier"))
    assert s_full["overall"]["passed"] == 0 and s_abl["overall"]["passed"] == 6
    assert s_abl["requires"] == ["recall", "fix", "scope_safety"]


def test_trial_outcome_rules():
    pos, neg = TASKS["P4-ghsa-aaaa"], TASKS["P4-neg-a-fixed"]
    ok = {"reward": 1.0, "recall": 1.0, "fix": 1.0, "claim_fidelity": 1.0, "scope_safety": 1.0, "fp": 1.0}
    o = R.trial_outcome({"task_id": "x", "rewards": ok, "unscored": False}, pos)
    assert o["passed"] and o["fp"] is None and o["scores"]["recall"] == 1.0
    o = R.trial_outcome({"task_id": "x", "rewards": {**ok, "fp": 0.0}, "unscored": False}, neg)
    assert not o["passed"] and o["fp"] == 1 and o["scores"]["recall"] is None
    o = R.trial_outcome({"task_id": "x", "rewards": None, "error": "Boom: x"}, pos)
    assert o["error"] and o["unscored"] and not o["passed"]
    o = R.trial_outcome({"task_id": "x", "rewards": ok, "unscored": False,
                         "details": {"hidden_test_passes": {"score": 0, "reasoning": "hidden_patch_conflict"}}}, pos)
    assert o["hidden_patch_conflict"]


# ----------------------------------------------------------------- refusals and dry runs

def _tasks_file(tmp_path: Path) -> Path:
    p = tmp_path / "tasks.jsonl"
    p.write_text("".join(json.dumps(t.to_record()) + "\n" for t in TASKS.values()))
    return p


def _run(tmp_path: Path, **kw):
    args = dict(split="train", model="claude-sonnet-5-5", trials=2, budget_usd=5.0, condition="class-blind",
                concurrency=2, ablation=None, anchor=False, unseal_test=False, out_dir=tmp_path / "res", dry_run=True,
                tasks_path=_tasks_file(tmp_path), splits_dir=tmp_path / "splits", log=None)
    args.update(kw)
    return R.run_calib(**args)


def test_run_calib_refuses_without_model_or_budget_and_sealed_test(tmp_path: Path):
    with pytest.raises(R.CalibError, match="--model is required"):
        _run(tmp_path, model=None)
    with pytest.raises(R.CalibError, match="--budget-usd"):
        _run(tmp_path, budget_usd=0)
    with pytest.raises(R.CalibError, match="--budget-usd"):
        _run(tmp_path, budget_usd=None)
    with pytest.raises(R.SealedTestError):
        _run(tmp_path, split="test")
    plan = _run(tmp_path, split="test", unseal_test=True)
    assert plan["split"] == "test" and plan["unseal_test"] is True
    with pytest.raises(R.CalibError, match="disabled"):
        _run(tmp_path, baseline="codex")
    with pytest.raises(R.CalibError, match="anchor list is empty"):
        _run(tmp_path, anchor=True)
    with pytest.raises(R.CalibError, match="--env"):
        _run(tmp_path, env="apple-container")
    assert not (tmp_path / "res").exists()                          # refusals and dry runs write nothing


def test_run_calib_dry_run_prints_argv_and_writes_nothing(tmp_path: Path, capsys):
    plan = _run(tmp_path, log=print)
    out = capsys.readouterr().out
    assert "argv: harbor run -p" in out and "dry run: nothing written" in out
    argv = plan["argv"]
    assert argv[:6] == ["harbor", "run", "-p", str(tmp_path / "splits" / "train"), "-a", "evals.agent.harbor_agent:SecurityAgent"]
    assert argv[argv.index("-m") + 1] == "claude-sonnet-5-5" and argv[argv.index("-k") + 1] == "2"
    assert "--ak" in argv and "condition=class-blind" in argv and "version=0.1.1" in argv
    cap = [a for a in argv if a.startswith("budget_usd=")][0]
    assert float(cap.split("=")[1]) == round(5.0 / (3 * 2), 6)       # 3 train tasks x 2 trials
    assert argv[argv.index("-e") + 1] == "docker" and plan["provenance"]["backend"] == "docker"
    assert plan["tasks_selected"] == ["P4-ghsa-aaaa", "P4-ghsa-bbbb", "P4-neg-a-fixed"]
    assert not (tmp_path / "res").exists()
    # ablation changes the condition name and the requires list; baseline kwargs are honoured
    plan = _run(tmp_path, ablation="no_verifier", condition="class-aware")
    assert plan["condition"] == "class-aware+no_verifier" and plan["requires"] == ["recall", "fix", "scope_safety"]
    plan = _run(tmp_path, baseline="nop", model=None, env="modal")
    assert "-m" not in plan["argv"] and plan["argv"][plan["argv"].index("-a") + 1] == "nop" and plan["env"] == "modal"
    plan = _run(tmp_path, baseline="codex", allow_disabled=True)
    assert plan["provenance"]["network"] == "allowlist" and "allowlist" in plan["provenance"]["condition_asymmetry"]


def test_calib_run_cli_exit_codes_and_dry_run(tmp_path: Path, capsys):
    out_dir = tmp_path / "res"
    base = ["calib-run", "--split", "train", "--out", str(out_dir), "--dry-run"]
    assert cli(base + ["--budget-usd", "5"]) == 2                    # no --model
    assert "--model is required" in capsys.readouterr().err
    assert cli(base + ["--model", "m"]) == 2                         # no --budget-usd
    assert cli(base + ["--model", "m", "--budget-usd", "0"]) == 2
    assert cli(["calib-run", "--split", "test", "--model", "m", "--budget-usd", "1", "--dry-run", "--out", str(out_dir)]) == 2
    assert "--unseal-test" in capsys.readouterr().err
    assert cli(base + ["--model", "m", "--budget-usd", "1"]) == 0
    out = capsys.readouterr().out
    assert "argv: harbor run -p" in out and "dry run" in out
    assert not out_dir.exists()
    assert cli(["calib-nope"]) == 2
    with pytest.raises(SystemExit):
        cli(["calib-compare"])


def test_run_calib_runs_a_fake_harbor_and_writes_the_run_dir(tmp_path: Path):
    calls = []

    def fake_runner(argv, **kw):
        calls.append(argv)
        jobs_dir = Path(argv[argv.index("-o") + 1])
        write_job(jobs_dir / argv[argv.index("--job-name") + 1])
        return type("P", (), {"returncode": 0})()

    s = _run(tmp_path, dry_run=False, runner=fake_runner, harbor_bin="/nonexistent/harbor", log=None)
    assert calls and calls[0][0] == "/nonexistent/harbor"
    run_dir = Path(s["run_dir"])
    for f in ("plan.json", "summary.json", "report.md", "samples.jsonl"):
        assert (run_dir / f).is_file(), f
    assert (tmp_path / "res" / "latest-calib.json").is_file()
    rows = [json.loads(l) for l in (run_dir / "samples.jsonl").read_text().splitlines()]
    assert len(rows) == 10 and {"passed", "value", "unscored", "metadata", "condition"} <= set(rows[0])
    assert rows[0]["metadata"]["backend"] == "docker"
    assert s["overall"]["n"] == 9 and s["provenance"]["harbor_rc"] == 0 and s["run_id"] == run_dir.name
    # calib-compare on the run against itself: delta 0
    res = R.run_compare(str(run_dir), run_dir.name, results_dir=tmp_path / "res", log=None)
    assert res["n"] == 5 and res["bootstrap"]["delta"] == 0.0 and res["mcnemar"]["p"] == 1.0


# ----------------------------------------------------------------- validity gate

def test_run_validate_dry_run_prints_two_argvs_and_writes_nothing(tmp_path: Path, capsys):
    r = R.run_validate(out_dir=tmp_path / "res", dry_run=True, tasks_dir=Path("/t/tasks"))
    out = capsys.readouterr().out
    assert "argv[nop]: harbor run -p /t/tasks -a nop" in out and "argv[oracle]: harbor run -p /t/tasks -a oracle" in out
    assert r["dry_run"] and set(r["argv"]) == {"nop", "oracle"} and not (tmp_path / "res").exists()
    assert cli(["calib-validate", "--dry-run", "--out", str(tmp_path / "res2")]) == 0
    assert "argv[oracle]" in capsys.readouterr().out and not (tmp_path / "res2").exists()
    with pytest.raises(R.CalibError):
        R.run_validate(out_dir=tmp_path, mode="local", dry_run=True)


def _rec(task, hidden, hrc, suite=1.0, error=""):
    return {"task_id": task, "error": error, "details": R.parse_reward_details(_details(hidden, hrc, suite))}


def test_validity_rc_rules():
    pos, neg = TASKS["P4-ghsa-aaaa"], TASKS["P4-neg-a-fixed"]
    good = R.validity_from_records([_rec(pos.task_id, 0.0, 1), _rec(neg.task_id, 1.0, 0)],
                                   [_rec(pos.task_id, 1.0, 0), _rec(neg.task_id, 1.0, 0)], [pos, neg])
    assert all(r.valid for r in good)
    assert good[0].details == {"noop_rc": 1, "noop_suite_rc": 0, "reference_rc": 0, "reference_suite_rc": 0}
    assert good[0].noop_fix == 0.0 and good[0].reference_fix == 1.0 and good[0].mode == "harbor"
    bad = R.validity_from_records([_rec(pos.task_id, 1.0, 0)], [_rec(pos.task_id, 1.0, 0)], [pos])[0]
    assert not bad.valid and bad.reason == "noop_passes"
    coll = R.validity_from_records([_rec(pos.task_id, 0.0, 2)], [_rec(pos.task_id, 1.0, 0)], [pos])[0]
    assert coll.reason == "noop_collection_error"
    ref = R.validity_from_records([_rec(pos.task_id, 0.0, 1)], [_rec(pos.task_id, 0.0, 1)], [pos])[0]
    assert ref.reason == "reference_fails"
    suite = R.validity_from_records([_rec(pos.task_id, 0.0, 1, suite=0.0)], [_rec(pos.task_id, 1.0, 0)], [pos])[0]
    assert "suite_fails_at_vuln" in suite.reason
    missing = R.validity_from_records([], [], [pos])[0]
    assert missing.reason == "no_nop_result,no_oracle_result"
    neg_bad = R.validity_from_records([_rec(neg.task_id, 1.0, 0, suite=0.0)], [_rec(neg.task_id, 1.0, 0)], [neg])[0]
    assert neg_bad.reason == "suite_fails_at_vuln"


# ----------------------------------------------------------------- baselines, registry, build hooks

def test_load_baselines_is_data_with_the_a4_schema():
    rows = R.load_baselines()
    names = [b["name"] for b in rows]
    assert names[0] == "ours" and {"nop", "oracle", "mini-swe-agent", "terminus-2", "openhands-sdk", "claude-code", "codex",
                                   "semgrep", "codeql", "bandit", "pysa"} <= set(names)
    assert "openhands" not in names and "aider" not in names
    by = {b["name"]: b for b in rows}
    assert by["ours"]["enabled"] and by["ours"]["harbor_agent"] == "evals.agent.harbor_agent:SecurityAgent"
    assert by["ours"]["kind"] == "ours" and by["ours"]["agent_kwargs"] == {"condition": "class-blind"}
    assert by["nop"]["kind"] == "control" and by["nop"]["enabled"] and by["oracle"]["harbor_agent"] == "oracle"
    for n in ("claude-code", "codex", "mini-swe-agent", "openhands-sdk", "terminus-2"):
        assert by[n]["kind"] == "generic" and not by[n]["enabled"] and by[n]["network"] == "allowlist"
    assert "2026-11-27" in by["codex"]["note"]
    for n in ("semgrep", "codeql", "bandit", "pysa"):
        b = by[n]
        assert b["kind"] == "sast" and not b["enabled"] and b["adapter"].startswith("evals.calib.sast:")
        assert b["invocation"] and b["license_note"] and b["needs_image_tools"]
        mod, fn = b["adapter"].split(":")
        assert mod == "evals.calib.sast" and callable(getattr(sast, fn))
    # the list is not a constant anywhere in code
    src = (REPO / "evals" / "calib" / "runner.py").read_text() + (REPO / "evals" / "cards.py").read_text()
    assert "mini-swe-agent" not in src and "terminus-2" not in src
    with pytest.raises(R.CalibError):
        R.baseline_by_name("nope", rows)


def test_load_baselines_validates(tmp_path: Path):
    p = tmp_path / "b.yaml"
    p.write_text(yaml.safe_dump({"baselines": [{"name": "x", "kind": "weird", "harbor_agent": "x", "enabled": True}]}))
    with pytest.raises(ValueError, match="kind"):
        R.load_baselines(p)
    p.write_text(yaml.safe_dump({"baselines": [{"name": "s", "kind": "sast", "harbor_agent": "x", "enabled": False}]}))
    with pytest.raises(ValueError, match="invocation"):
        R.load_baselines(p)


def test_registry_entry_has_every_readme_field():
    e = R.load_calib_registry()
    readme = (REPO / "evals" / "registry" / "calib" / "README.md").read_text()
    fields = {m.group(1) for m in re.finditer(r"^\| `([a-z_]+)(?:\.[a-z_]+)?` \|", readme, re.M)}
    assert fields <= set(e), fields - set(e)
    assert e["id"] == EVAL_ID and e["tasks"] == "evals/calib/egress/tasks.jsonl" and e["harbor_version"] == "0.27.0"
    assert e["splits"]["test_hash"] == "" and e["splits"]["counts"] == {"train": 0, "validation": 0, "test": 0, "negatives": 0}
    assert e["splits"]["fractions"] == [0.5, 0.2, 0.3] and e["anchor"] == []
    assert e["primary_metric"] == {"name": "class_blind_recall_and_fpr", "split": "test", "condition": "class-blind", "ci": "wilson95"}
    assert e["conditions"] == ["class-blind", "class-aware", "class-blind+no_verifier"]
    assert e["canary"] == (REPO / "evals" / "registry" / "CANARY.txt").read_text().strip()
    assert REGISTRY_FILE.is_file() and list(e["graders"]) == list(SCORE_NAMES)


def test_registry_prompt_hashes_agree_with_prompts_when_present():
    prompts = pytest.importorskip("evals.agent.prompts")     # W-C's module; skipped on this branch
    e = R.load_calib_registry()
    task = TASKS["P4-ghsa-aaaa"]
    for mode in ("class-blind", "class-aware"):
        want = prompts.prompt_hashes(task, prompts.Condition.parse(mode))
        assert e["prompt_hashes"][mode] == want, f"registry prompt_hashes.{mode} must be {want} (fill at integration)"


def test_build_hooks_without_wb(tmp_path: Path, capsys):
    cands = tmp_path / "c.jsonl"
    cands.write_text(json.dumps({"ghsa_id": "GHSA-x", "status": "selected"}) + "\n")
    rc = cli(["calib-build", "--dry-run", "--candidates", str(cands)])
    err = capsys.readouterr().err
    assert rc in (0, 2)
    if rc == 2:
        assert "evals.calib.build is not on this checkout" in err
    assert cli(["calib-ingest"]) in (0, 2)


def test_resolve_digests_dry_run_shape_and_refusal(capsys):
    assert R.digest_argv("python:3.12-slim") == ["docker", "manifest", "inspect", "--verbose", "python:3.12-slim"]
    assert R.resolve_digests(dry_run=True) == 0
    out = capsys.readouterr().out
    assert "argv: docker manifest inspect --verbose python:3.12-slim" in out and "nothing written" in out
    with pytest.raises(R.CalibError, match="docker"):
        R.resolve_digests(dry_run=False, available=lambda: False)
    assert R.docker_available(which=lambda _: None) is False
    assert cli(["calib-build", "--resolve-digests", "--dry-run"]) == 0


def test_condition_names():
    assert R.condition_name("class-blind", None) == "class-blind"
    assert R.condition_name("class-aware", "no_verifier") == "class-aware+no_verifier"
    assert R.condition_requires(None) == tuple(SCORE_NAMES) and "claim_fidelity" not in R.condition_requires("no_verifier")
    with pytest.raises(R.CalibError):
        R.condition_name("blind", None)
    with pytest.raises(R.CalibError):
        R.condition_name("class-blind", "no_tests")


# ----------------------------------------------------------------- SAST adapters

SCHEMA = json.loads((REPO / "agents" / "report.schema.json").read_text())


def _check_report(rep: Dict, tool: str) -> None:
    assert set(SCHEMA["required"]) <= set(rep) and rep["agent"] == tool and rep["property"] == "P4" and rep["claims"] == []
    for f in rep["findings"]:
        assert set(SCHEMA["properties"]["findings"]["items"]["required"]) <= set(f)
        assert isinstance(f["line"], int) and f["status"] in ("fixed", "open", "accepted-risk")
        assert not f["file"].startswith("/") and not f["file"].startswith("./")
        if "severity" in f:
            assert f["severity"] in ("high", "medium", "low")


def test_sarif_adapter():
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": [
        {"ruleId": "py/full-ssrf", "level": "error", "message": {"text": "request depends on a user-provided value"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/app/pkg/fetch.py"}, "region": {"startLine": 42}}}]},
        {"ruleId": "py/partial-ssrf", "message": {"text": "m"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "pkg/other.py"}, "region": {"startLine": 7}}},
                       {"physicalLocation": {"artifactLocation": {"uri": "pkg/other.py"}, "region": {"startLine": 7}}}]},
        {"ruleId": "no-location", "locations": []}]}]}
    rep = sast.sarif_to_report(sarif, tool="codeql", commit="c" * 40)
    _check_report(rep, "codeql")
    assert [(f["id"], f["file"], f["line"]) for f in rep["findings"]] == [("py/full-ssrf", "pkg/fetch.py", 42), ("py/partial-ssrf", "pkg/other.py", 7)]
    assert rep["findings"][0]["severity"] == "high" and rep["commit"] == "c" * 40


def test_semgrep_bandit_pysa_adapters():
    sg = {"results": [{"check_id": "python.requests.security.disabled-cert-validation", "path": "/app/pkg/a.py",
                       "start": {"line": 3, "col": 1}, "extra": {"message": "cert validation off", "severity": "WARNING"}}]}
    rep = sast.semgrep_to_report(sg)
    _check_report(rep, "semgrep")
    assert rep["findings"] == [{"id": "python.requests.security.disabled-cert-validation", "file": "pkg/a.py", "line": 3,
                                "evidence": "python.requests.security.disabled-cert-validation: cert validation off",
                                "status": "open", "severity": "medium"}]
    bd = {"results": [{"test_id": "B310", "test_name": "blacklist", "filename": "./pkg/b.py", "line_number": 12,
                       "issue_severity": "MEDIUM", "issue_text": "Audit url open"}]}
    rep = sast.bandit_to_report(bd)
    _check_report(rep, "bandit")
    assert rep["findings"][0] == {"id": "B310", "file": "pkg/b.py", "line": 12, "evidence": "B310: blacklist",
                                  "status": "open", "severity": "medium"}
    py = [{"code": 5001, "name": "Server-side request forgery", "path": "pkg/c.py", "line": 9}, "junk"]
    rep = sast.pysa_to_report(py)
    _check_report(rep, "pysa")
    assert rep["findings"][0]["id"] == "pysa-5001" and rep["findings"][0]["file"] == "pkg/c.py"
    assert sast.pysa_to_report({"issues": py})["findings"] == rep["findings"]
    assert sast.semgrep_to_report({})["findings"] == [] and sast.bandit_to_report({"results": []})["findings"] == []
    assert set(sast.ADAPTERS) == {"sarif", "semgrep", "bandit", "pysa"}


# ----------------------------------------------------------------- card

def test_calib_card_sections(tmp_path: Path, capsys):
    e = R.load_calib_registry()
    text = cards.render_calib_card(e, list(TASKS.values()), None)
    for h in ("## Dataset Summary", "## Supported Tasks", "## Languages", "## Dataset Structure", "## Dataset Creation",
              "### Curation Rationale", "### Source Data", "### Annotations", "## Considerations", "### Social Impact",
              "### Biases", "### Limitations", "## Additional Information", "### Licensing", "### Citation",
              "## Splits", "## Contamination", "## Power", "## Exclusions", "## Baselines", "## Not measured"):
        assert h in text, h
    assert "Miller" in text and "K-trials rule" in text and "arXiv 2411.00640" in text
    assert "hidden_patch_conflict" in text and "tar" in text and "proxy" in text and "Selection bias" in text
    assert "no external comparison" in text and "GHSA" not in text.split("## Dataset Creation")[0]
    assert "| openhands-sdk | generic |" in text and "| ours | ours |" in text and "P4-ghsa-aaaa" in text
    assert "no stable, permissively licensed" in text
    assert cli(["card", "calib-egress"]) == 0
    assert capsys.readouterr().out.startswith("# Dataset card")
    with pytest.raises(ValueError):
        cards.calib_card("calib-nothing")


# ----------------------------------------------------------------- the agent gate

def _agent_summary(tasks_passed: Dict[str, bool], *, errors: int = 0, run_id="r1", **overrides) -> Dict:
    from evals.metrics import wilson_ci
    n = len(tasks_passed)
    passed = sum(tasks_passed.values())
    block = {"n": n, "tasks": n, "trials": 1, "passed": passed, "errors": errors,
             "pass_rate": round(passed / n, 3), "pass_rate_ci95": [round(x, 3) for x in wilson_ci(passed, n)]}
    for s in SCORE_NAMES:
        block[s] = round(passed / n, 3)
        block[f"{s}_ci95"] = block["pass_rate_ci95"]
    block.update(overrides)
    return {"run_id": run_id, "git_sha": "abc", "toolkit_version": "0.1.1", "model": "m", "condition": "class-blind",
            "split": "train", "trials": 1, "overall": block, "evals": {EVAL_ID: block},
            "tasks": [{"task_id": t, "eval_id": EVAL_ID, "property": "P4", "passed": p, "error": None, "trials": 1,
                       "passes": int(p)} for t, p in tasks_passed.items()]}


def test_decide_agent_rules(tmp_path: Path):
    base_s = _agent_summary({f"t{i}": True for i in range(20)})
    base = gate.agent_baseline_from_summary(base_s, "v1", published="2026-11-27")
    assert base["kind"] == "agent" and set(base["evals"][EVAL_ID]) >= {"pass_rate", "pass_rate_ci95", "recall_ci95", "errors"}
    assert gate.decide_agent(base, base_s).exit_code == 0
    # a named flip fails even when the aggregate stays inside the interval
    flip = _agent_summary({**{f"t{i}": True for i in range(19)}, "t19": False})
    d = gate.decide_agent(base, flip)
    assert d.exit_code == 1 and d.named[0][0] == "t19"
    # a score below the lower bound fails, and names the metric
    low = _agent_summary({f"t{i}": True for i in range(20)}, scope_safety=0.5)
    d = gate.decide_agent(base, low)
    assert d.exit_code == 1 and any("scope_safety" in f for r in d.rows for f in r.failures)
    # errors fail
    err = _agent_summary({f"t{i}": True for i in range(20)}, errors=1)
    assert gate.decide_agent(base, err).exit_code == 1
    # a missing eval cannot be evaluated
    assert gate.decide_agent(base, {**base_s, "evals": {}}).exit_code == 2
    # a detector baseline is refused
    with pytest.raises(gate.GateError):
        gate.decide_agent({"kind": None, "label": "x"}, base_s)
    text = gate.render_decision(d, base, gate.AGENT_METRICS)
    assert "agent baseline v1" in text and "pass_rate (baseline -> new)" in text


def test_agent_gate_cli_publish_and_gate(tmp_path: Path, capsys):
    bdir = tmp_path / "agent-baselines"
    s = _agent_summary({"a": True, "b": True, "c": False})
    sfile = tmp_path / "summary.json"
    sfile.write_text(json.dumps(s))
    assert cli(["gate", "--agent", "--baselines", str(bdir), "--summary", str(sfile)]) == 2
    assert cli(["baseline", "publish", "--agent", "--label", "v1", "--summary", str(sfile), "--baselines", str(bdir)]) == 0
    assert "published agent baseline v1" in capsys.readouterr().out
    assert json.loads((bdir / "v1.json").read_text())["kind"] == "agent" and (bdir / "latest.json").is_file()
    assert cli(["gate", "--agent", "--baselines", str(bdir), "--summary", str(sfile)]) == 0
    assert "GATE: PASS" in capsys.readouterr().out
    worse = tmp_path / "worse.json"
    worse.write_text(json.dumps(_agent_summary({"a": True, "b": False, "c": False})))
    assert cli(["gate", "--agent", "--against", "v1", "--baselines", str(bdir), "--summary", str(worse)]) == 1
    assert "Named regressions (1" in capsys.readouterr().out
    # the detector gate refuses an agent baseline directory's entry
    assert cli(["baseline", "publish", "--agent", "--label", "v1", "--summary", str(sfile), "--baselines", str(bdir)]) == 2
    # a summary without `tasks` (agent-run shape) gets them from samples.jsonl beside it
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    s2 = {k: v for k, v in s.items() if k != "tasks"}
    (run_dir / "summary.json").write_text(json.dumps(s2))
    rows = [{"task_id": "a", "variant": "agent", "passed": True, "eval_id": EVAL_ID, "stop_reason": "done"},
            {"task_id": "a", "variant": "noop", "passed": False, "eval_id": EVAL_ID, "stop_reason": "done"},
            {"task_id": "b", "variant": "agent", "passed": False, "eval_id": EVAL_ID, "stop_reason": "error",
             "failure_reason": "api: boom"}]
    (run_dir / "samples.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    tasks = gate.agent_summary_tasks(s2, run_dir)
    assert [(t["task_id"], t["passed"], t["error"]) for t in tasks] == [("a", True, None), ("b", False, "api: boom")]
    assert cli(["gate", "--agent", "--baselines", str(bdir), "--summary", str(run_dir / "summary.json")]) == 1


def test_detector_gate_unchanged_signature():
    # the detector path still uses recall/precision and ignores agent metrics
    assert gate.DETECTOR_METRICS == ("recall", "precision")
    import inspect
    assert list(inspect.signature(gate.decide).parameters) == ["baseline", "summary"]
