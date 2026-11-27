"""evals/agent/harbor_agent.py without harbor: the module imports, SecurityAgent refuses to
spend without a budget, HarborEnv adapts argv -> shell string, a full trial runs against a
fake environment + the loop tests' FakeClient, to_atif is ATIF-v1.8-shaped, SastAgent wraps a
fake analyser through a fake adapter. No model, no key, no docker, no harbor, no rewardkit."""
from __future__ import annotations

import asyncio
import json
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals import calib
from evals.agent import harbor_agent as ha
from evals.agent.types import DenialEvent, LoopResult, Usage

from test_agent_loop import FakeClient, GOOD_REPORT, message, text, tool_use, usage  # noqa: E402

INSTRUCTION = ("Review this repository at /app for security vulnerabilities. Fix what you find with minimal, "
               "targeted edits; do not refactor unrelated code; do not add or modify files under tests/ except "
               "to add a regression test for a fix. Run the project's test suite "
               "(`python -m pytest tests -q -x -p no:cacheprovider`) after editing. When done, write a JSON "
               "report to /logs/artifacts/report.json.")
FORBIDDEN = ("P4", "egress", "SSRF", "fetch", "redirect", "safe_fetch", "CWE-918")


def _leaks(text: str) -> dict:
    """Whole-word, case-insensitive (the instruction's "regression" contains "egress")."""
    return {w: len(re.findall(r"(?<![A-Za-z0-9_])" + re.escape(w) + r"(?![A-Za-z0-9_])", text, re.I)) for w in FORBIDDEN}


class FakeEnvironment:
    """Harbor BaseEnvironment stand-in: async exec/upload_file/download_file, recorded."""

    def __init__(self, rc: int = 0, stdout: str = "", stderr: str = "", downloads=None):
        self.rc, self.stdout, self.stderr = rc, stdout, stderr
        self.execs: list[tuple[str, str | None, int | None]] = []
        self.uploads: list[tuple[str, str]] = []          # (target, content)
        self.downloads = downloads or {}
        self.download_calls: list[str] = []

    async def exec(self, command: str, cwd=None, env=None, timeout_sec=None, user=None):
        self.execs.append((command, cwd, timeout_sec))
        return SimpleNamespace(stdout=self.stdout, stderr=self.stderr, return_code=self.rc)

    async def upload_file(self, source_path, target_path: str):
        self.uploads.append((target_path, Path(source_path).read_text()))

    async def download_file(self, source_path: str, target_path):
        self.download_calls.append(source_path)
        if source_path not in self.downloads:
            raise OSError(f"no such file {source_path}")
        Path(target_path).write_text(self.downloads[source_path])


# --------------------------------------------------------------------- import / construction

def test_module_imports_without_harbor():
    assert ha.HARBOR_AVAILABLE is False and ha.BaseAgent is object
    assert "harbor" not in sys.modules
    assert ha.SecurityAgent.name() == "security-agents" and ha.SastAgent.name() == "security-agents-sast"
    assert ha.SecurityAgent.MODEL_CONNECTION is None and ha.SastAgent.MODEL_CONNECTION is None
    assert ha.SecurityAgent.capabilities == {"atif": True}
    assert (ha.PROVIDER, list(ha.API_KEY_ENV), ha.API_FORMAT) == ("anthropic", ["ANTHROPIC_API_KEY"], "anthropic_messages")


def test_security_agent_defaults_and_options(tmp_path):
    a = ha.SecurityAgent(tmp_path)
    assert a.budget_usd == 0.0 and a.condition.name == "class-blind" and a.agent_spec == "agents/egress.md"
    assert a.model_name is None and a.logs_dir == tmp_path
    b = ha.SecurityAgent(tmp_path, "anthropic/claude-haiku-5-5", condition="class-aware+no_verifier", budget_usd="0.25")
    assert b.budget_usd == 0.25 and b.condition.passed_requires == ("recall", "fix", "scope_safety")
    assert re.fullmatch(r"\d+\.\d+\.\d+", b.version())
    with pytest.raises(ValueError):
        ha.SecurityAgent(tmp_path, condition="nope")


def test_security_agent_refuses_without_budget_before_any_request(tmp_path):
    env = FakeEnvironment()
    ctx = SimpleNamespace()
    agent = ha.SecurityAgent(tmp_path, "anthropic/claude-haiku-5-5")           # budget_usd defaults to 0.0
    agent._client = FakeClient(message(text("hi"), stop_reason="end_turn"))
    with pytest.raises(ValueError, match="budget_usd"):
        asyncio.run(agent.run(INSTRUCTION, env, ctx))
    assert env.execs == [] and env.uploads == [] and agent._client.requests == []
    assert not (tmp_path / "trajectory.json").exists()
    with pytest.raises(ValueError, match="budget_usd"):
        asyncio.run(ha.SecurityAgent(tmp_path, "x", budget_usd=-1).run(INSTRUCTION, env, ctx))


def test_security_agent_refuses_without_model(tmp_path):
    env = FakeEnvironment()
    with pytest.raises(ValueError, match="model"):
        asyncio.run(ha.SecurityAgent(tmp_path, None, budget_usd=1.0).run(INSTRUCTION, env, SimpleNamespace()))
    assert env.execs == []


# --------------------------------------------------------------------- pure helpers

def test_bare_model_name():
    assert ha.bare_model_name("anthropic/claude-sonnet-5-5") == "claude-sonnet-5-5"
    assert ha.bare_model_name("claude-haiku-5-5") == "claude-haiku-5-5"
    assert ha.bare_model_name(" openrouter/anthropic/claude-x ") == "anthropic/claude-x"
    assert ha.bare_model_name("") == ""


def test_suite_and_task_from_instruction():
    assert ha.suite_from_instruction(INSTRUCTION) == ["python", "-m", "pytest", "tests", "-q", "-x", "-p", "no:cacheprovider"]
    assert ha.suite_from_instruction("run `pytest -q` please") == ["pytest", "-q"]
    assert ha.suite_from_instruction("no backticks here") == list(ha.DEFAULT_SUITE)
    assert ha.suite_from_instruction("see `/logs/artifacts/report.json` and `ls`") == list(ha.DEFAULT_SUITE)
    t = ha.task_from_instruction(INSTRUCTION, agent_spec="agents/egress.md")
    assert t.repo == "/app" and t.kind == "advisory" and t.description == "" and t.property == calib.PROPERTY
    assert t.container_test == ha.suite_from_instruction(INSTRUCTION) and t.scope_rule == "reachable-from-fix"
    assert t.agent == "agents/egress.md" and t.eval_id == calib.EVAL_ID


# --------------------------------------------------------------------- HarborEnv

def test_harbor_env_exec_joins_argv_maps_python_and_uses_app_cwd():
    fake = FakeEnvironment(rc=3, stdout="out", stderr="err")
    env = ha.HarborEnv(fake)
    assert env.mode == "harbor" and env.workdir == Path("/app")
    r = env.exec(["python", "-c", "print('a b')", "x y"], timeout_s=42)
    assert fake.execs == [("python3 -c 'print('\"'\"'a b'\"'\"')' 'x y'", "/app", 42)]
    assert (r.returncode, r.stdout, r.stderr, r.timed_out) == (3, "out", "err", False) and r.seconds >= 0
    env.exec(["grep", "-rn", "--include=*.py", "-e", "-x", "."])
    assert fake.execs[-1][0] == "grep -rn '--include=*.py' -e -x ."
    env.exec(["python3", "-V"])
    assert fake.execs[-1][0] == "python3 -V"
    assert env.calls[-1] == "python3 -V"


def test_harbor_env_timeout_and_sync_fakes():
    class Hanging:
        async def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
            raise asyncio.TimeoutError()

    r = ha.HarborEnv(Hanging()).exec(["python", "-m", "pytest"], timeout_s=5)
    assert r.returncode == 124 and r.timed_out and "timeout" in r.stderr

    class Sync:
        def exec(self, command, cwd=None, env=None, timeout_sec=None, user=None):
            return SimpleNamespace(stdout="s", stderr=None, return_code=124)

    r = ha.HarborEnv(Sync()).exec(["ls"])
    assert r.returncode == 124 and r.timed_out and r.stderr == ""


def test_harbor_env_diff_and_protocol():
    fake = FakeEnvironment(stdout="DIFF")
    env = ha.HarborEnv(fake)
    assert env.diff() == "DIFF"
    assert [c[0] for c in fake.execs] == ["git add -N .", "git diff --no-color", "git reset -q"]
    with pytest.raises(NotImplementedError):
        env.reset(None)
    env.close()


# --------------------------------------------------------------------- a whole trial, offline

def _run_agent(tmp_path, condition="class-blind", client=None, fake=None):
    fake = fake or FakeEnvironment(stdout="1\timport os\n[1-1 of 1 lines]\n")
    agent = ha.SecurityAgent(tmp_path / "logs", "anthropic/claude-haiku-5-5", condition=condition, budget_usd=1.0)
    agent._client = client or FakeClient(
        message(text("Reading."), tool_use("read_file", path="pkg/client.py"), usage=usage(100, 20)),
        message(tool_use("run_tests"), usage=usage(200, 30, cr=50)),
        message(tool_use("write_report", report=GOOD_REPORT), usage=usage(300, 40)),
    )
    ctx = SimpleNamespace(n_input_tokens=None, n_cache_tokens=None, n_output_tokens=None, cost_usd=None, metadata=None)
    asyncio.run(agent.run(INSTRUCTION, fake, ctx))
    return agent, fake, ctx


def test_full_trial_class_blind(tmp_path):
    agent, fake, ctx = _run_agent(tmp_path)
    client = agent._client
    # prompts: the system prompt is the generic spec; the user message starts with Harbor's instruction
    path, kw = client.requests[0]
    assert kw["system"].startswith("# Generic security agent")
    assert _leaks(kw["system"]) == {w: 0 for w in FORBIDDEN}, _leaks(kw["system"])
    assert _leaks(kw["messages"][0]["content"]) == {w: 0 for w in FORBIDDEN}, _leaks(kw["messages"][0]["content"])
    assert kw["messages"][0]["content"].startswith(INSTRUCTION)
    # tools went through the sandbox as shell strings in /app, python mapped to python3
    cmds = [c for c in fake.execs if c[1] == "/app"]
    assert cmds[0][0].startswith("python3 -c ") and cmds[0][0].endswith(" pkg/client.py 1 400")
    assert ("python3 -m pytest tests -q -x -p no:cacheprovider", "/app", 600) in fake.execs
    # the report reached /logs/artifacts/report.json via upload_file from a temp file
    assert [t for t, _ in fake.uploads] == [calib.REPORT_ARTIFACT]
    assert json.loads(fake.uploads[0][1]) == GOOD_REPORT
    assert any(c[0] == "mkdir -p /logs/artifacts" for c in fake.execs)
    # context
    assert (ctx.n_input_tokens, ctx.n_cache_tokens, ctx.n_output_tokens) == (650, 50, 90)
    assert ctx.cost_usd == pytest.approx((600 * 0.10 + 90 * 0.50 + 50 * 0.01) / 1e6)
    assert ctx.metadata["condition"] == "class-blind" and ctx.metadata["stop_reason"] == "done"
    assert ctx.metadata["report_written"] is True and ctx.metadata["tool_calls"] == 3
    assert set(ctx.metadata["prompt_hashes"]) == {"system", "user"}
    # trajectory
    traj = json.loads((tmp_path / "logs" / "trajectory.json").read_text())
    assert traj["schema_version"] == calib.ATIF_SCHEMA_VERSION == "ATIF-v1.8"
    assert [s["step_id"] for s in traj["steps"]] == [1, 2, 3, 4, 5]
    assert traj["steps"][2]["tool_calls"][0]["function_name"] == "read_file"
    assert traj["final_metrics"]["total_cost_usd"] == pytest.approx(ctx.cost_usd)


def test_full_trial_class_aware_and_no_report(tmp_path):
    client = FakeClient(message(text("nothing to do"), stop_reason="end_turn", usage=usage(10, 5)))
    agent, fake, ctx = _run_agent(tmp_path, condition="class-aware+no_verifier", client=client)
    _, kw = client.requests[0]
    assert kw["system"].startswith("# Egress agent") and "The miss" not in kw["system"]
    assert "Property: P4" in kw["messages"][0]["content"]
    assert fake.uploads == [] and ctx.metadata["report_written"] is False
    assert ctx.metadata["failure_reason"] == "no report" and ctx.metadata["passed_requires"] == ["recall", "fix", "scope_safety"]
    traj = json.loads((tmp_path / "logs" / "trajectory.json").read_text())
    assert len(traj["steps"]) == 2 and traj["extra"]["report_written"] is False


def test_trajectory_and_context_written_even_when_the_loop_raises(tmp_path):
    class Boom:
        messages = SimpleNamespace(stream=lambda **kw: (_ for _ in ()).throw(RuntimeError("kaboom")))
        beta = SimpleNamespace(messages=messages)

    with pytest.raises(RuntimeError):
        _run_agent(tmp_path, client=Boom())
    traj = json.loads((tmp_path / "logs" / "trajectory.json").read_text())
    assert traj["extra"]["stop_reason"] == "error" and traj["final_metrics"]["total_cost_usd"] == 0.0


# --------------------------------------------------------------------- to_atif

def _lr(**over) -> LoopResult:
    base = dict(stop_reason="done", report=GOOD_REPORT, tool_calls=4,
                denials=[DenialEvent(tool="shell", reason="unknown_tool", call_index=3)],
                usage=Usage(1000, 150, 50, 10), cost_usd=0.0123, model="claude-haiku-5-5", failure_reason="",
                transcript=[
                    {"turn": 1, "tool": "list_files", "args_summary": {}, "path": None, "result_chars": 9, "is_error": False, "result": "./a.py"},
                    {"turn": 1, "tool": "grep", "args_summary": {"pattern": 3}, "path": None, "result_chars": 2, "is_error": False, "result": "no matches"},
                    {"turn": 2, "tool": "", "args_summary": {}, "result_chars": 0, "is_error": True, "result": "unparseable tool JSON (turn re-issued)"},
                    {"turn": 3, "tool": "shell", "args_summary": {"cmd": 2}, "path": None, "result_chars": 6, "is_error": True, "result": "denied (unknown_tool)", "denial": "unknown_tool"},
                    {"turn": 4, "tool": "write_report", "args_summary": {"report": 200}, "path": None, "result_chars": 15, "is_error": False, "result": "report accepted"},
                ], elapsed_s=12.3456)
    base.update(over)
    return LoopResult(**base)


ALLOWED_KEYS = {
    "trajectory": {"schema_version", "session_id", "trajectory_id", "agent", "steps", "notes", "final_metrics",
                   "continued_trajectory_ref", "extra", "subagent_trajectories"},
    "agent": {"name", "version", "model_name", "tool_definitions", "extra"},
    "step": {"step_id", "timestamp", "source", "model_name", "reasoning_effort", "message", "reasoning_content",
             "tool_calls", "observation", "metrics", "is_copied_context", "llm_call_count", "extra"},
    "tool_call": {"tool_call_id", "function_name", "arguments", "extra"},
    "observation": {"results"},
    "result": {"source_call_id", "content", "subagent_trajectory_ref", "extra"},
    "final_metrics": {"total_prompt_tokens", "total_completion_tokens", "total_cached_tokens", "total_cost_usd",
                      "total_steps", "extra"},
}


def _check_atif(traj: dict) -> None:
    """The field table of harbor.models.trajectories (every model is extra="forbid")."""
    assert set(traj) <= ALLOWED_KEYS["trajectory"] and traj["schema_version"] == "ATIF-v1.8"
    assert set(traj["agent"]) <= ALLOWED_KEYS["agent"] and traj["agent"]["name"] and traj["agent"]["version"]
    assert len(traj["steps"]) >= 1
    for i, step in enumerate(traj["steps"], 1):
        assert set(step) <= ALLOWED_KEYS["step"] and step["step_id"] == i
        assert step["source"] in ("system", "user", "agent") and isinstance(step["message"], str)
        if step["source"] != "agent":
            for k in ("model_name", "reasoning_effort", "reasoning_content", "tool_calls", "metrics"):
                assert step.get(k) is None
        ids = set()
        for tc in step.get("tool_calls") or []:
            assert set(tc) <= ALLOWED_KEYS["tool_call"] and isinstance(tc["arguments"], dict)
            assert tc["tool_call_id"] and tc["function_name"]
            ids.add(tc["tool_call_id"])
        if step.get("observation") is not None:
            assert set(step["observation"]) <= ALLOWED_KEYS["observation"]
            for r in step["observation"]["results"]:
                assert set(r) <= ALLOWED_KEYS["result"] and r["source_call_id"] in ids
        if step.get("llm_call_count") == 0 and step["source"] == "agent":
            assert step.get("metrics") is None and step.get("reasoning_content") is None
    fm = traj["final_metrics"]
    assert set(fm) <= ALLOWED_KEYS["final_metrics"] and fm["total_steps"] == len(traj["steps"])
    json.dumps(traj)


def test_to_atif_shape():
    traj = ha.to_atif(_lr(), model="claude-haiku-5-5", instruction="USER", system="SYSTEM", agent_version="0.1.1")
    _check_atif(traj)
    steps = traj["steps"]
    assert [s["source"] for s in steps] == ["system", "user", "agent", "agent", "agent", "agent"]
    assert steps[0]["message"] == "SYSTEM" and steps[1]["message"] == "USER"
    turn1 = steps[2]
    assert [tc["function_name"] for tc in turn1["tool_calls"]] == ["list_files", "grep"]
    assert turn1["tool_calls"][1]["arguments"] == {"args_summary": {"pattern": 3}}
    assert [r["source_call_id"] for r in turn1["observation"]["results"]] == [tc["tool_call_id"] for tc in turn1["tool_calls"]]
    assert turn1["observation"]["results"][1]["content"] == "no matches"
    assert steps[3]["tool_calls"] is None if "tool_calls" in steps[3] else True
    assert "re-issued" in steps[3]["message"] and "observation" not in steps[3]
    assert steps[4]["observation"]["results"][0]["content"].startswith("[denied: unknown_tool]")
    assert traj["agent"] == {"name": "security-agents", "version": "0.1.1", "model_name": "claude-haiku-5-5",
                             "extra": {"loop": "evals.agent.loop.run_trial"}}
    assert traj["final_metrics"] == {"total_prompt_tokens": 1060, "total_completion_tokens": 150, "total_cached_tokens": 50,
                                     "total_cost_usd": 0.0123, "total_steps": 6}
    assert traj["extra"]["denials"] == 1 and traj["extra"]["tool_calls"] == 4 and traj["extra"]["report_written"] is True


def test_to_atif_empty_transcript_and_arguments_never_hold_values():
    traj = ha.to_atif(_lr(transcript=[], report=None, stop_reason="error", failure_reason="api: X"),
                      model="m", instruction="u", system="s", agent_version="v")
    _check_atif(traj)
    assert len(traj["steps"]) == 2 and traj["extra"]["report_written"] is False
    traj = ha.to_atif(_lr(transcript=[{"turn": 1, "tool": "edit_file", "args_summary": {"path": 8, "old": 5, "new": 7},
                                       "path": "pkg/a.py", "result_chars": 2, "is_error": False, "result": "ok"}]),
                      model="m", instruction="u", system="s", agent_version="v")
    _check_atif(traj)
    assert traj["steps"][2]["tool_calls"][0]["arguments"] == {"args_summary": {"path": 8, "old": 5, "new": 7}, "path": "pkg/a.py"}


def test_minimal_atif_shape():
    traj = ha.minimal_atif(agent_name="security-agents-sast", version="1.2", instruction="i", tool="semgrep",
                           arguments={"invocation": "semgrep ..."}, observation="rc=0")
    _check_atif(traj)
    assert traj["steps"][1]["llm_call_count"] == 0 and traj["final_metrics"]["total_cost_usd"] == 0.0


# --------------------------------------------------------------------- SastAgent

def test_output_path_of_and_resolve_adapter():
    assert ha.output_path_of("semgrep scan --config p/python --json -o /tmp/semgrep.json /app") == "/tmp/semgrep.json"
    assert ha.output_path_of("bandit -r /app -f json -o /tmp/bandit.json -t B310") == "/tmp/bandit.json"
    assert ha.output_path_of("codeql database analyze db --format=sarif-latest --output=/tmp/r.sarif") == "/tmp/r.sarif"
    assert ha.output_path_of("tool --output /tmp/x.json") == "/tmp/x.json" and ha.output_path_of("tool run") == ""
    assert ha.output_path_of("tool 'unterminated") == ""
    assert ha.resolve_adapter("json:dumps") is json.dumps and ha.resolve_adapter("json.dumps") is json.dumps
    with pytest.raises(ValueError):
        ha.resolve_adapter("json:no_such_function")
    with pytest.raises(ValueError):
        ha.resolve_adapter("nocolon")
    with pytest.raises(ImportError):
        ha.resolve_adapter("no_such_module_xyz:fn")


@pytest.fixture
def fake_adapter(monkeypatch):
    mod = types.ModuleType("fake_sast_adapter")
    calls = []

    def to_report(data, *, tool):
        calls.append((data, tool))
        return {"agent": tool, "property": "P4", "repo": "/app", "commit": "HEAD",
                "findings": [{"id": f"{tool}-1", "file": r["path"], "line": r["line"], "evidence": r["rule"], "status": "open"}
                             for r in data["results"]],
                "claims": []}
    mod.to_report = to_report
    mod.calls = calls
    monkeypatch.setitem(sys.modules, "fake_sast_adapter", mod)
    return mod


def test_sast_agent_runs_downloads_adapts_uploads(tmp_path, fake_adapter):
    out = json.dumps({"results": [{"path": "pkg/client.py", "line": 6, "rule": "python.requests.ssrf"}]})
    fake = FakeEnvironment(rc=1, stdout="findings: 1", downloads={"/tmp/semgrep.json": out})
    agent = ha.SastAgent(tmp_path / "logs", invocation="semgrep scan --json -o /tmp/semgrep.json /app",
                         adapter="fake_sast_adapter:to_report", tool="semgrep", version="1.99.0")
    assert agent.output == "/tmp/semgrep.json" and agent.version() == "1.99.0"
    ctx = SimpleNamespace()
    asyncio.run(agent.run(INSTRUCTION, fake, ctx))
    assert fake.execs[0] == ("semgrep scan --json -o /tmp/semgrep.json /app", "/app", ha.SAST_TIMEOUT_S)
    assert fake.download_calls == ["/tmp/semgrep.json"]
    assert fake_adapter.calls[0][1] == "semgrep"
    assert [t for t, _ in fake.uploads] == [calib.REPORT_ARTIFACT]
    report = json.loads(fake.uploads[0][1])
    assert report["findings"][0]["file"] == "pkg/client.py" and report["claims"] == []
    assert (ctx.n_input_tokens, ctx.n_output_tokens, ctx.cost_usd) == (0, 0, 0.0)
    assert ctx.metadata["rc"] == 1 and ctx.metadata["report_valid"] is True and ctx.metadata["n_findings"] == 1
    traj = json.loads((tmp_path / "logs" / "trajectory.json").read_text())
    _check_atif(traj)
    assert traj["agent"]["name"] == "security-agents-sast" and traj["steps"][1]["llm_call_count"] == 0
    assert traj["steps"][1]["observation"]["results"][0]["content"].startswith("rc=1")


def test_sast_agent_missing_output_and_bad_report(tmp_path, fake_adapter, monkeypatch):
    fake = FakeEnvironment(rc=0)                                        # nothing to download
    agent = ha.SastAgent(tmp_path / "l1", invocation="bandit -r /app -f json -o /tmp/b.json",
                         adapter="fake_sast_adapter:to_report", tool="bandit")
    ctx = SimpleNamespace()
    asyncio.run(agent.run(INSTRUCTION, fake, ctx))
    assert fake.uploads == [] and ctx.metadata["report_valid"] is False and "unreadable" in ctx.metadata["report_problem"]
    assert (tmp_path / "l1" / "trajectory.json").exists()
    # an adapter whose report fails the schema is not uploaded
    fake_adapter.to_report = lambda data, *, tool: {"agent": tool}
    fake = FakeEnvironment(rc=0, downloads={"/tmp/b.json": "{}"})
    agent = ha.SastAgent(tmp_path / "l2", invocation="bandit -o /tmp/b.json", adapter="fake_sast_adapter:to_report", tool="bandit")
    asyncio.run(agent.run(INSTRUCTION, fake, ctx))
    assert fake.uploads == [] and ctx.metadata["report_problem"] == "property: missing"


def test_sast_agent_refuses_incomplete_options(tmp_path):
    env = FakeEnvironment()
    with pytest.raises(ValueError, match="invocation"):
        asyncio.run(ha.SastAgent(tmp_path, adapter="json:dumps", tool="x").run("i", env, SimpleNamespace()))
    with pytest.raises(ValueError, match="output"):
        asyncio.run(ha.SastAgent(tmp_path, invocation="tool run", adapter="json:dumps", tool="x").run("i", env, SimpleNamespace()))
    with pytest.raises(ImportError):
        asyncio.run(ha.SastAgent(tmp_path, invocation="tool -o /tmp/x", adapter="no_mod_xyz:f", tool="x").run("i", env, SimpleNamespace()))
    assert env.execs == []                                               # every refusal is before the invocation runs
