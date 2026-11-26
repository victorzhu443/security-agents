"""W4: baselines + validity gate, runner layout, CLI, agent registry, CI workflow.

No model, no docker, no network: the Env, the fix grader, the loop and the task loader are
fakes installed with monkeypatch (runner imports its siblings lazily for exactly this)."""
import json
import re
import types
from pathlib import Path

import pytest
import yaml

from evals import __main__ as cli
from evals.agent import baselines, repos, runner
from evals.agent.types import (STOP_BUDGET, STOP_DONE, STOP_ERROR, DenialEvent, ExecResult, GradeResult,
                               LoopResult, ResetInfo, Scores, Task, Usage)
from evals.registry import canary

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "agent-evals.yml"
RRA = "research-replication-agent"
RRA_COMMIT = repos.load_repos()[RRA].commit
BASE = "def add(a, b):\n    return a + b\n"
TEST_CMD = ".venv/bin/python -m pytest tests/security -q"


def mk_task(tid, *, find="return a + b", replace="return a - b", prop="P4"):
    return Task(task_id=tid, eval_id=f"security.agent.{RRA}.v1", repo=RRA,
                repo_url=f"https://github.com/victorzhu443/{RRA}.git", commit=RRA_COMMIT, property=prop,
                description="a benign arithmetic stand-in", file="pkg/m.py", find=find, replace=replace,
                hidden_test=TEST_CMD, suite_test=TEST_CMD,
                container_test=["python", "-m", "pytest", "tests/security", "-q"], pythonpath=[],
                agent="agents/egress.md", canary=canary())


class FakeEnv:
    """reset writes the mutated file; exec returns 0 iff the file holds the reference text
    (the stand-in for the hidden test); diff returns a scripted string."""
    mode = "local"

    def __init__(self, root: Path, *, diff_text="", exec_rc=None, fail_reset=False):
        self.root, self.diff_text, self.exec_rc, self.fail_reset = Path(root), diff_text, exec_rc, fail_reset
        self.workdir = None
        self.closed = False
        self.task = None

    def reset(self, task):
        if self.fail_reset:
            raise RuntimeError("clone failed")
        self.task = task
        self.workdir = self.root / f"wd-{len(list(self.root.iterdir()))}"
        f = self.workdir / task.file
        f.parent.mkdir(parents=True)
        f.write_text(BASE.replace(task.find, task.replace))
        return ResetInfo(mode="local", workdir=self.workdir, limits={"nproc": 2048})

    def exec(self, argv, *, timeout_s=600):
        if self.exec_rc is not None:
            return ExecResult(self.exec_rc, "", "", 0.01)
        text = (self.workdir / self.task.file).read_text()
        return ExecResult(0 if self.task.find in text else 1, "", "", 0.01)

    def diff(self):
        return self.diff_text

    def close(self):
        self.closed = True


class FakeFixGrader:
    name = "fix"

    def grade(self, ctx):
        r = ctx.env.exec(ctx.task.container_test)
        return GradeResult(1.0 if r.returncode == 0 else 0.0, evidence=f"rc={r.returncode}")


@pytest.fixture
def gate(monkeypatch):
    calls = []

    def restore(task, env):
        calls.append(task.task_id)
        (env.workdir / task.file).write_text(BASE)

    monkeypatch.setattr(baselines, "_fix_grader", lambda: FakeFixGrader())
    monkeypatch.setattr(baselines, "_restore_reference", restore)
    return calls


# ----------------------------------------------------------------- validity gate

def test_validate_task_valid_when_noop_fails_and_reference_passes(tmp_path, gate):
    env = FakeEnv(tmp_path)
    r = baselines.validate_task(mk_task("ok"), env)
    assert (r.valid, r.noop_fix, r.reference_fix, r.reason, r.mode) == (True, 0.0, 1.0, "", "local")
    assert env.closed and r.seconds >= 0


def test_validate_task_quarantines_when_noop_passes(tmp_path, gate):
    # the "mutation" keeps the reference text, so the hidden test cannot see it
    r = baselines.validate_task(mk_task("weak", replace="return a + b  # mutated"), FakeEnv(tmp_path))
    assert not r.valid and r.noop_fix == 1.0 and r.reason == baselines.REASON_NOOP_PASSES


def test_validate_task_quarantines_when_reference_fails(tmp_path, gate):
    r = baselines.validate_task(mk_task("broken"), FakeEnv(tmp_path, exec_rc=1))
    assert not r.valid and (r.noop_fix, r.reference_fix) == (0.0, 0.0)
    assert r.reason == baselines.REASON_REFERENCE_FAILS


def test_validate_task_records_errors_and_still_closes(tmp_path, gate):
    env = FakeEnv(tmp_path, fail_reset=True)
    r = baselines.validate_task(mk_task("boom"), env)
    assert not r.valid and r.reason.startswith("error:") and "clone failed" in r.reason
    assert env.closed


def test_validate_reuses_the_reference_verdict_per_repo_and_test(tmp_path, gate):
    ts = [mk_task("a"), mk_task("b"), mk_task("c")]
    out = baselines.validate(ts, lambda: FakeEnv(tmp_path), log=None)
    assert [r.valid for r in out] == [True, True, True]
    assert [r.reference_fix for r in out] == [1.0, 1.0, 1.0]     # recorded per task
    assert gate == ["a"]                                           # computed once per group
    gate.clear()
    baselines.validate(ts, lambda: FakeEnv(tmp_path), log=None, reuse_reference=False)
    assert gate == ["a", "b", "c"]


def test_validate_survives_an_env_factory_that_raises(tmp_path, gate):
    def factory():
        raise RuntimeError("docker unavailable")
    out = baselines.validate([mk_task("x")], factory)
    assert not out[0].valid and out[0].reason.startswith("error: env:")


# ----------------------------------------------------------------- fakes for the runner

def install_fakes(monkeypatch, tmp_path, task_lists, *, loop_results=None, diff_text="", load_error=None):
    """Fake env/tasks/loop/graders modules on `runner`. `task_lists` maps repo -> tasks;
    `load_error` names a repo whose load raises (the environment-quarantine path)."""
    def load_all_tasks(selector):
        if selector == load_error:
            raise RuntimeError("clone needs a token")
        return {selector: task_lists.get(selector, [])}

    envs = []

    def make_env(mode):
        e = FakeEnv(tmp_path / "envs", diff_text=diff_text)
        envs.append(e)
        return e

    (tmp_path / "envs").mkdir(exist_ok=True)
    calls = []
    queue = list(loop_results or [])

    def run_trial(task, env, *, model, budget_usd, agent_body, log=None):
        calls.append({"task": task.task_id, "model": model, "budget_usd": budget_usd, "body": agent_body})
        assert env.workdir is not None, "run_trial must see a reset env"
        return queue.pop(0)

    def grade_all(ctx):
        if ctx.report is None:
            return Scores(evidence={"recall": "no report"})
        return Scores(recall=1.0, fix=1.0, claim_fidelity=1.0, scope_safety=1.0, evidence={"fix": "rc=0"})

    monkeypatch.setattr(runner, "tasks", types.SimpleNamespace(load_all_tasks=load_all_tasks))
    monkeypatch.setattr(runner, "env", types.SimpleNamespace(make_env=make_env))
    monkeypatch.setattr(runner, "loop", types.SimpleNamespace(run_trial=run_trial))
    monkeypatch.setattr(runner, "graders", types.SimpleNamespace(grade_all=grade_all))
    return calls, envs


def done(cost, *, tool_calls=5, denials=()):
    return LoopResult(stop_reason=STOP_DONE, report={"findings": [{"file": "pkg/m.py"}], "claims": []},
                      tool_calls=tool_calls, denials=list(denials),
                      usage=Usage(input_tokens=1000, output_tokens=200, cache_read_tokens=50, cache_write_tokens=10),
                      cost_usd=cost, model="fake-model", transcript=[{"tool": "read_file", "args_bytes": 20}],
                      elapsed_s=1.5)


def budget_stop(cost):
    return LoopResult(stop_reason=STOP_BUDGET, report=None, tool_calls=40, denials=[], usage=Usage(input_tokens=9),
                      cost_usd=cost, model="fake-model", failure_reason="budget: 40 tool calls")


# ----------------------------------------------------------------- agent-validate

def test_run_validate_writes_layout_and_returns_quarantine_reasons(tmp_path, gate, monkeypatch):
    install_fakes(monkeypatch, tmp_path, {RRA: [mk_task("ok"), mk_task("weak", replace="return a + b  #")]})
    out = runner.run_validate(RRA, out_dir=tmp_path / "res", mode="auto", log=None)
    run_dir = Path(out["run_dir"])
    assert run_dir.parent == tmp_path / "res" and re.match(r"\d{8}T\d{6}Z-", run_dir.name)
    doc = json.loads((run_dir / "validity.json").read_text())
    assert [r["task_id"] for r in doc["results"]] == ["ok", "weak"]
    assert out["valid"] == ["ok"] and doc["valid"] == ["ok"]
    assert out["quarantined"] == [{"task_id": "weak", "eval_id": f"security.agent.{RRA}.v1",
                                   "reason": baselines.REASON_NOOP_PASSES}]
    assert out["mode"] == "local" and out["per_repo"] == {RRA: {"tasks": 2}}
    assert "| weak |" in (run_dir / "report.md").read_text()
    latest = json.loads((tmp_path / "res" / "latest-agent-validate.json").read_text())
    assert latest["run_id"] == out["run_id"]


def test_run_validate_reports_an_unloadable_repo_as_environment_quarantine(tmp_path, gate, monkeypatch):
    install_fakes(monkeypatch, tmp_path, {RRA: [mk_task("ok")]}, load_error="study-hub")
    logs = []
    out = runner.run_validate("all", out_dir=tmp_path / "res", log=logs.append)
    assert out["valid"] == ["ok"]
    env_q = [q for q in out["quarantined"] if q["task_id"] == "study-hub/*"]
    assert len(env_q) == 1 and env_q[0]["reason"].startswith("environment:")
    assert "error" in out["per_repo"]["study-hub"]
    assert any(l.startswith("task") for l in logs)        # the printed table


def test_run_validate_only_filters_by_id_or_property(tmp_path, gate, monkeypatch):
    install_fakes(monkeypatch, tmp_path, {RRA: [mk_task("a", prop="P4"), mk_task("b", prop="P5")]})
    out = runner.run_validate(RRA, out_dir=tmp_path / "res", only="P5", log=None)
    assert out["valid"] == ["b"]


# ----------------------------------------------------------------- agent-run

def test_run_agent_requires_model_and_budget(tmp_path):
    with pytest.raises(ValueError, match="model"):
        runner.run_agent([mk_task("a")], model="", budget_usd=1.0, out_dir=tmp_path)
    with pytest.raises(ValueError, match="budget"):
        runner.run_agent([mk_task("a")], model="m", budget_usd=None, out_dir=tmp_path)
    with pytest.raises(ValueError, match="budget"):
        runner.run_agent([mk_task("a")], model="m", budget_usd=0, out_dir=tmp_path)


def test_run_agent_gates_runs_grades_and_writes_the_layout(tmp_path, gate, monkeypatch):
    diff = "diff --git a/pkg/m.py b/pkg/m.py\n--- a/pkg/m.py\n+++ b/pkg/m.py\n"
    tasks = [mk_task("t1"), mk_task("t2"), mk_task("weak", replace="return a + b  #")]
    # t1: pass, budget-stop; t2: pass, then the run cap (1.2 >= 1.0) stops the 4th trial
    calls, envs = install_fakes(monkeypatch, tmp_path, {RRA: tasks}, diff_text=diff,
                                loop_results=[done(0.4), budget_stop(0.3), done(0.5, denials=[DenialEvent("x", "unknown_tool")])])
    logs = []
    s = runner.run_agent(RRA, model="fake-model", trials=2, budget_usd=1.0, out_dir=tmp_path / "res", log=logs.append)
    run_dir = Path(s["run_dir"])

    # planned line before the first model call, with the per-trial cap arithmetic
    planned = [l for l in logs if l.startswith("planned:")]
    assert planned == ["planned: 2 tasks x 2 trials = 4 trials, per-trial cap $0.2500, run cap $1.00, model fake-model"]
    assert not any(l.startswith("warning:") for l in logs)
    assert len(calls) == 3 and all(c["budget_usd"] == pytest.approx(1.0 / 4) for c in calls)
    assert all(not c["body"].startswith("---") and "# Egress agent" in c["body"] for c in calls)
    assert all(e.closed for e in envs)

    # samples.jsonl: 2 valid tasks x (noop + reference + 2 trials)
    lines = [json.loads(l) for l in (run_dir / "samples.jsonl").read_text().splitlines()]
    assert len(lines) == 8
    assert [(l["task_id"], l["variant"], l["trial"]) for l in lines] == [
        ("t1", "noop", 0), ("t1", "reference", 0), ("t1", "agent", 1), ("t1", "agent", 2),
        ("t2", "noop", 0), ("t2", "reference", 0), ("t2", "agent", 1), ("t2", "agent", 2)]
    assert {l["scores"]["fix"] for l in lines if l["variant"] == "noop"} == {0.0}
    assert {l["scores"]["fix"] for l in lines if l["variant"] == "reference"} == {1.0}
    agent = [l for l in lines if l["variant"] == "agent"]
    assert [a["passed"] for a in agent] == [True, False, True, False]
    assert agent[1]["stop_reason"] == STOP_BUDGET and agent[1]["scores"]["errors"] == {"trial": "budget: 40 tool calls"}
    assert agent[3]["stop_reason"] == STOP_BUDGET and agent[3]["failure_reason"] == runner.RUN_BUDGET_EXHAUSTED
    assert agent[3]["cost_usd"] == 0 and agent[2]["denials"][0]["reason"] == "unknown_tool"
    assert set(agent[0]["provenance"]) >= {"mode", "repo", "repo_commit", "toolkit_version", "toolkit_sha",
                                           "model", "image", "image_digest", "python", "platform"}
    assert agent[0]["provenance"]["mode"] == "local" and agent[0]["provenance"]["repo_commit"] == RRA_COMMIT
    assert set(agent[0]["tokens"]) == {"input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens", "total"}

    # summary.json
    summ = json.loads((run_dir / "summary.json").read_text())
    for k in ("run_id", "generated", "model", "mode", "trials", "budget_usd", "cost_usd_total", "toolkit_version",
              "git_sha", "provenance", "overall", "evals", "_reading"):
        assert k in summ, k
    o = summ["overall"]
    assert (o["n"], o["tasks"], o["passed"]) == (4, 2, 2)
    assert o["pass_rate"] == 0.5 and len(o["pass_rate_ci95"]) == 2
    for sc in ("recall", "fix", "claim_fidelity", "scope_safety"):
        assert o[sc] == 0.5 and o[f"{sc}_ci95"][0] < 0.5 < o[f"{sc}_ci95"][1]
    assert o["pass_at_k"]["1"] == 0.5 and o["pass_at_k"]["2"] == 1.0
    assert o["pass_pow_k"] == {"1": 0.5, "2": 0.25}
    assert o["cost_usd_total"] == pytest.approx(1.2) and o["cost_usd_per_task"] == pytest.approx(0.6)
    assert o["tokens"]["total"] == 2 * 1260 + 9 and o["denials"] == 1 and o["budget_stops"] == 2
    assert o["quarantined"] == [{"task_id": "weak", "eval_id": f"security.agent.{RRA}.v1",
                                 "reason": baselines.REASON_NOOP_PASSES}]
    assert o["baselines"] == {"noop_fix_mean": 0.0, "reference_fix_mean": 1.0}
    assert summ["provenance"]["mode"] == "local" and summ["provenance"]["repos"][RRA]["commit"] == RRA_COMMIT
    assert list(summ["evals"]) == [f"security.agent.{RRA}.v1"] and summ["evals"][f"security.agent.{RRA}.v1"]["n"] == 4

    # report, validity, transcripts, latest pointer
    report = (run_dir / "report.md").read_text()
    assert "fake-model" in report and "| weak |" in report and "## Provenance" in report and "| t1 | 2 |" in report
    assert json.loads((run_dir / "validity.json").read_text())["valid"] == ["t1", "t2"]
    assert sorted(p.name for p in (run_dir / "transcripts").iterdir()) == ["t1-1.json", "t1-2.json", "t2-1.json"]
    assert json.loads((run_dir / "transcripts" / "t1-1.json").read_text())["transcript"][0]["tool"] == "read_file"
    assert json.loads((tmp_path / "res" / "latest-agent.json").read_text())["run_id"] == s["run_id"]


def test_run_agent_warns_above_the_pilot_allocation_and_records_harness_errors(tmp_path, gate, monkeypatch):
    def exploding(task, env, **kw):
        raise RuntimeError("api down")
    install_fakes(monkeypatch, tmp_path, {RRA: [mk_task("t1")]})
    monkeypatch.setattr(runner.loop, "run_trial", exploding)
    logs = []
    s = runner.run_agent(RRA, model="m", trials=1, budget_usd=6, out_dir=tmp_path / "res", log=logs.append)
    assert any(l.startswith("warning:") and "$6.00" in l for l in logs)
    rows = [json.loads(l) for l in (Path(s["run_dir"]) / "samples.jsonl").read_text().splitlines()]
    agent = [r for r in rows if r["variant"] == "agent"]
    assert len(agent) == 1 and agent[0]["stop_reason"] == STOP_ERROR and "api down" in agent[0]["failure_reason"]
    assert s["overall"]["errors"] == 1 and s["overall"]["passed"] == 0


def test_run_agent_with_nothing_valid_writes_an_empty_summary(tmp_path, gate, monkeypatch):
    calls, _ = install_fakes(monkeypatch, tmp_path, {RRA: [mk_task("weak", replace="return a + b  #")]})
    s = runner.run_agent(RRA, model="m", trials=3, budget_usd=1, out_dir=tmp_path / "res", log=None)
    assert calls == [] and s["overall"]["n"] == 0 and s["overall"]["pass_at_k"] == {"1": None, "2": None, "3": None}
    assert len(s["overall"]["quarantined"]) == 1


def test_agent_body_strips_front_matter(tmp_path):
    p = tmp_path / "a.md"
    p.write_text("---\nname: x\ntools: Read\n---\n\n# Agent\n\nbody\n")
    assert runner.agent_body(p) == "# Agent\n\nbody\n"
    assert runner.agent_body(REPO / "agents" / "egress.md").startswith("# Egress agent")


# ----------------------------------------------------------------- registry

def test_load_agent_registry_validates_the_four_entries():
    reg = runner.load_agent_registry()
    assert set(reg) == {f"security.agent.{r}.v1" for r in
                        ("research-replication-agent", "smart-dispatch", "firstplay-backend", "study-hub")}
    cfgs = repos.load_repos()
    for eid, e in reg.items():
        assert e["commit"] == cfgs[e["repo"]].commit and e["canary"] == canary()
        assert (e["split"], e["source"]) == ("build", "real-codebase")
        assert e["graders"] == ["recall", "fix", "claim_fidelity", "scope_safety"]
        assert e["metrics"] == ["pass_at_k", "pass_pow_k", "cost_usd_per_task"]
        assert e["owner_agent"] == "agents/README.md" and e["catalogue"] == "security/mutations.yaml"
    assert (runner.AGENT_REGISTRY_DIR / "README.md").exists()


@pytest.mark.parametrize("field,value,match", [
    ("commit", "0" * 40, "commit"), ("canary", "not the canary", "canary"),
    ("split", "heldout", "split"), ("id", "security.agent.other.v1", "id"),
])
def test_load_agent_registry_rejects_a_tampered_copy(tmp_path, field, value, match):
    for f in runner.AGENT_REGISTRY_DIR.glob("*.yaml"):
        (tmp_path / f.name).write_text(f.read_text())
    data = yaml.safe_load((tmp_path / "study-hub.yaml").read_text())
    data[field] = value
    (tmp_path / "study-hub.yaml").write_text(yaml.safe_dump(data))
    with pytest.raises(ValueError, match=match):
        runner.load_agent_registry(tmp_path)


def test_agent_registry_does_not_disturb_the_property_registry():
    from evals.registry import load_registry
    assert not any("agent" in eid for eid in load_registry())


# ----------------------------------------------------------------- CLI

def test_cli_agent_run_requires_model_and_budget():
    with pytest.raises(SystemExit) as ei:
        cli.main(["agent-run", "--repo", "all"])
    assert ei.value.code == 2
    with pytest.raises(SystemExit) as ei:
        cli.main(["agent-run", "--repo", "all", "--model", "m"])
    assert ei.value.code == 2
    assert "agent-run --repo" in cli.USAGE and "agent-validate --repo" in cli.USAGE


def test_cli_dispatches_to_the_runner(monkeypatch, tmp_path):
    seen = {}

    def fake_validate(repo, *, out_dir, mode, only, log=print):
        seen.update(repo=repo, out_dir=out_dir, mode=mode, only=only)
        return {}

    def fake_run(repo, *, model, trials, budget_usd, out_dir, mode, only, log=print):
        seen.update(run=(repo, model, trials, budget_usd, mode))
        return {}

    monkeypatch.setattr(runner, "run_validate", fake_validate)
    monkeypatch.setattr(runner, "run_agent", fake_run)
    assert cli.main(["agent-validate", "--repo", "all", "--out", str(tmp_path), "--mode", "local"]) == 0
    assert (seen["repo"], seen["out_dir"], seen["mode"], seen["only"]) == ("all", tmp_path, "local", None)
    assert cli.main(["agent-run", "--repo", RRA, "--model", "claude-haiku-5-5", "--budget-usd", "5", "--out", str(tmp_path)]) == 0
    assert seen["run"] == (RRA, "claude-haiku-5-5", 1, 5.0, "auto")


# ----------------------------------------------------------------- CI workflow

def test_workflow_is_dispatch_only_pinned_and_guards_the_pilot():
    text = WORKFLOW.read_text()
    wf = yaml.safe_load(text)
    on = wf.get("on", wf.get(True))            # PyYAML reads a bare `on:` key as True
    assert set(on) == {"workflow_dispatch"}
    rp = on["workflow_dispatch"]["inputs"]["run_pilot"]
    assert rp["type"] == "boolean" and rp["default"] is False
    assert wf["permissions"] == {"contents": "read"}
    job = wf["jobs"]["validate"]
    assert job["timeout-minutes"] == 60
    steps = job["steps"]
    for s in steps:
        if "uses" in s:
            assert re.search(r"@[0-9a-f]{40}$", s["uses"]), s["uses"]
    runs = [s.get("run", "") for s in steps]
    assert any("agent-validate --repo all --mode container" in r for r in runs)
    pilot = [s for s in steps if "agent-run" in s.get("run", "")]
    assert len(pilot) == 1 and "run_pilot" in pilot[0]["if"] and "HAS_KEY" in pilot[0]["if"]
    assert "--model claude-haiku-5-5 --trials 1 --budget-usd 5" in pilot[0]["run"]
    assert pilot[0]["env"]["ANTHROPIC_API_KEY"] == "${{ secrets.ANTHROPIC_API_KEY }}"
    clone = [s for s in steps if "study-hub" in s.get("run", "")]
    assert len(clone) == 1 and clone[0]["continue-on-error"] is True and "HAS_TOKEN" in clone[0]["if"]
    assert clone[0]["env"]["TOOLKIT_TOKEN"] == "${{ secrets.TOOLKIT_TOKEN }}"
    assert "secrets." not in pilot[0]["if"] and "secrets." not in clone[0]["if"]   # env indirection
    flags = [s for s in steps if "HAS_TOKEN=" in s.get("run", "")]
    assert len(flags) == 1 and steps.index(flags[0]) < steps.index(clone[0]) < steps.index(pilot[0])
    assert "pip install -e \".[agent]\"" in text
    assert "NOT set by this PR" in text and "ANTHROPIC_API_KEY" in text and "TOOLKIT_TOKEN" in text
    upload = [s for s in steps if "upload-artifact" in s.get("uses", "")]
    assert len(upload) == 1 and upload[0]["if"] == "always()"


def test_run_refuses_to_start_on_rejected_credential(tmp_path, monkeypatch):
    """A placeholder or invalid key must stop the run before the gate, with exit 2 and no run dir."""
    from evals.agent import loop as L, runner as R
    def boom(client=None):
        raise L.AuthPreflightError("credential rejected")
    monkeypatch.setattr(L, "preflight_auth", boom)
    rc = R.main_run(["--repo", "research-replication-agent", "--model", "claude-haiku-5-5",
                     "--trials", "1", "--budget-usd", "1", "--out", str(tmp_path)])
    assert rc == 2
    assert not any(p.is_dir() for p in tmp_path.iterdir()) if tmp_path.exists() else True


def test_preflight_auth_wraps_sdk_errors():
    import anthropic, httpx
    from evals.agent import loop as L
    class Bad:
        class models:
            @staticmethod
            def list(limit=1):
                raise anthropic.AuthenticationError("invalid x-api-key", response=httpx.Response(401, request=httpx.Request("GET", "https://x")), body=None)
    with pytest.raises(L.AuthPreflightError):
        L.preflight_auth(Bad())
    class Good:
        class models:
            @staticmethod
            def list(limit=1):
                class P: data = [type("M", (), {"id": "claude-haiku-5-5"})()]
                return P()
    assert L.preflight_auth(Good()) == "claude-haiku-5-5"
