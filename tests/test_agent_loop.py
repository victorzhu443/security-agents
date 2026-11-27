"""evals/agent/loop.py: tool schemas, budget arithmetic, cost, and the streaming tool loop
driven by a scripted FakeClient against a FakeEnv. No network, no key, no `anthropic` import
(except one importorskip-guarded shape check that constructs no client)."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.agent import loop
from evals.agent.loop import (
    BudgetGuard,
    cost_usd,
    load_prices,
    run_trial,
    tool_definitions,
    validate_report,
)
from evals.agent.types import (
    MAX_TOOL_CALLS,
    MAX_TOTAL_TOKENS,
    STOP_BUDGET,
    STOP_DONE,
    STOP_ERROR,
    STOP_REFUSAL,
    TOOLS,
    ExecResult,
    Task,
    Usage,
)

PLANTED = "sk-ant-FAKE0000"


# --------------------------------------------------------------------- fakes

def make_task(**over) -> Task:
    base = dict(
        task_id="P4-demo", eval_id="security.agent.demo.v1", repo="demo",
        repo_url="https://example.invalid/demo.git", commit="0" * 40, property="P4",
        description="every fetch goes through safe_fetch", file="pkg/fetch.py",
        find="safe_fetch(", replace="requests.get(",
        hidden_test=".venv/bin/python -m pytest tests/security -q",
        suite_test=".venv/bin/python -m pytest tests/security -q",
        container_test=["python", "-m", "pytest", "tests/security", "-q"],
        pythonpath=[], agent="agents/egress.md", canary="CANARY",
    )
    base.update(over)
    return Task(**base)


class FakeEnv:
    """Records every argv; answers with scripted ExecResults (default: ok, empty)."""

    def __init__(self, workdir: Path, mode: str = "local"):
        self.mode = mode
        self.workdir = workdir
        self.calls: list[list[str]] = []
        self.script: list[ExecResult] = []

    def push(self, stdout: str = "", returncode: int = 0, stderr: str = "", timed_out: bool = False):
        self.script.append(ExecResult(returncode=returncode, stdout=stdout, stderr=stderr,
                                      seconds=0.01, timed_out=timed_out))

    def exec(self, argv, *, timeout_s: int = 600) -> ExecResult:
        assert isinstance(argv, (list, tuple)) and all(isinstance(a, str) for a in argv), argv
        self.calls.append(list(argv))
        if self.script:
            return self.script.pop(0)
        return ExecResult(returncode=0, stdout="", stderr="", seconds=0.01)

    def reset(self, task):  # pragma: no cover - not used by the loop
        raise NotImplementedError

    def diff(self) -> str:  # pragma: no cover
        return ""

    def close(self) -> None:  # pragma: no cover
        pass


def usage(inp=100, out=50, cr=0, cw=0):
    return SimpleNamespace(input_tokens=inp, output_tokens=out,
                           cache_read_input_tokens=cr, cache_creation_input_tokens=cw)


def tool_use(name, _id=None, **args):
    tool_use.n = getattr(tool_use, "n", 0) + 1
    return SimpleNamespace(type="tool_use", id=_id or f"toolu_{tool_use.n:03d}", name=name, input=args)


def text(t):
    return SimpleNamespace(type="text", text=t)


def message(*blocks, stop_reason="tool_use", usage=usage()):
    return SimpleNamespace(content=list(blocks), stop_reason=stop_reason, usage=usage)


class _FakeStream:
    def __init__(self, item):
        self.item = item

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        if isinstance(self.item, BaseException):
            raise self.item
        return self.item


class _FakeMessages:
    def __init__(self, owner, path):
        self.owner = owner
        self.path = path

    def stream(self, **kwargs):
        snap = dict(kwargs)
        snap["messages"] = list(kwargs["messages"])      # the loop mutates its list in place
        self.owner.requests.append((self.path, snap))
        if not self.owner.script:
            raise AssertionError("FakeClient script exhausted")
        return _FakeStream(self.owner.script.pop(0))


class FakeClient:
    """`messages.stream(**kw)` / `beta.messages.stream(**kw)` return a context manager whose
    `get_final_message()` yields the next scripted message (or raises a scripted exception)."""

    def __init__(self, *script):
        self.script = list(script)
        self.requests: list[tuple[str, dict]] = []
        self.messages = _FakeMessages(self, "messages")
        self.beta = SimpleNamespace(messages=_FakeMessages(self, "beta.messages"))


GOOD_REPORT = {
    "agent": "egress-agent", "property": "P4", "repo": "demo", "commit": "0" * 40,
    "findings": [{"id": "P4-1", "file": "pkg/fetch.py", "line": 12,
                  "evidence": "requests.get(url)", "status": "fixed", "severity": "high"}],
    "claims": [{"statement": "all fetches pinned", "oracle": "python -m pytest tests/security -q",
                "evidence": "3 passed"}],
}


def run(client, env, task=None, model="claude-haiku-5-5", budget=1.0, **kw):
    return run_trial(task or make_task(), env, model=model, budget_usd=budget,
                     agent_body="You are the egress agent.", client=client, **kw)


# --------------------------------------------------------------------- tool definitions

def test_tool_definitions_shape():
    defs = tool_definitions()
    assert tuple(d["name"] for d in defs) == TOOLS
    for d in defs:
        assert d["strict"] is True
        assert d["eager_input_streaming"] is True
        schema = d["input_schema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert isinstance(schema["required"], list)
        assert set(schema["required"]) <= set(schema["properties"])
        assert d["description"]
    by = {d["name"]: d["input_schema"] for d in defs}
    assert by["run_tests"]["properties"] == {} and by["run_tests"]["required"] == []
    assert by["write_report"]["properties"] == {"report": by["write_report"]["properties"]["report"]}
    assert by["write_report"]["properties"]["report"]["type"] == "object"
    assert by["write_report"]["required"] == ["report"]
    assert by["edit_file"]["required"] == ["path", "old", "new"]
    assert by["read_file"]["required"] == ["path"]
    assert by["grep"]["required"] == ["pattern"]
    json.dumps(defs)  # serializable as sent


def test_tool_definitions_accepted_by_sdk_type():
    anthropic = pytest.importorskip("anthropic")
    from anthropic.types import ToolParam  # TypedDict: check keys, construct no client
    allowed = set(ToolParam.__annotations__)
    for d in tool_definitions():
        assert set(d) <= allowed, (d["name"], set(d) - allowed)
    assert anthropic.__version__


# --------------------------------------------------------------------- budget guard

def test_budget_guard_trips_at_the_41st_call():
    g = BudgetGuard(max_usd=100.0)
    for _ in range(MAX_TOOL_CALLS):
        assert g.note_call() is None
    reason = g.note_call()
    assert reason and reason.startswith("budget:") and "41 tool calls" in reason


def test_budget_guard_tokens_boundary():
    g = BudgetGuard(max_usd=100.0)
    assert g.note_usage(Usage(input_tokens=MAX_TOTAL_TOKENS - 1), 0.0) is None
    reason = g.note_usage(Usage(output_tokens=1), 0.0)
    assert reason and reason.startswith("budget:") and f"{MAX_TOTAL_TOKENS} tokens" in reason
    # cache tokens count toward the total
    g2 = BudgetGuard(max_usd=100.0)
    assert g2.note_usage(Usage(cache_read_tokens=MAX_TOTAL_TOKENS), 0.0)


def test_budget_guard_usd_boundary():
    g = BudgetGuard(max_usd=0.50)
    assert g.note_usage(Usage(), 0.25) is None
    assert g.note_usage(Usage(), 0.2499) is None
    reason = g.note_usage(Usage(), 0.0001)
    assert reason and reason.startswith("budget:") and "$" in reason


def test_budget_guard_custom_limits():
    g = BudgetGuard(2, 10, max_usd=1.0)
    assert g.note_call() is None and g.note_call() is None and g.note_call()
    assert g.note_usage(Usage(input_tokens=10), 0.0)


# --------------------------------------------------------------------- cost

def test_cost_usd_against_prices_yaml():
    prices = load_prices()
    assert prices["as_of"] == "2026-11-26"
    u = Usage(input_tokens=1_000_000, output_tokens=1_000_000, cache_read_tokens=1_000_000,
              cache_write_tokens=1_000_000)
    assert cost_usd(u, "claude-haiku-5-5", prices) == pytest.approx(0.10 + 0.50 + 0.01 + 0.125)
    assert cost_usd(u, "claude-sonnet-5-5", prices) == pytest.approx(2.00 + 10.00 + 0.20 + 2.50)
    assert cost_usd(u, "claude-opus-5-5", prices) == pytest.approx(4.00 + 20.00 + 0.20 + 5.00)
    small = Usage(input_tokens=1234, output_tokens=567)
    assert cost_usd(small, "claude-haiku-5-5", prices) == pytest.approx((1234 * 0.10 + 567 * 0.50) / 1e6)
    assert cost_usd(Usage(), "claude-opus-5-5", prices) == 0.0


def test_cost_usd_unknown_model_names_it():
    with pytest.raises(ValueError, match="claude-nope-9"):
        cost_usd(Usage(input_tokens=1), "claude-nope-9", load_prices())


def test_run_trial_rejects_unpriced_model_before_any_request(tmp_path):
    client = FakeClient()
    with pytest.raises(ValueError, match="claude-nope-9"):
        run(client, FakeEnv(tmp_path), model="claude-nope-9")
    assert client.requests == []


# --------------------------------------------------------------------- happy path

def test_happy_path_read_edit_test_report(tmp_path):
    env = FakeEnv(tmp_path)
    env.push("1\timport requests\n2\tr = requests.get(url)\n[1-2 of 2 lines]\n")  # read_file
    env.push("ok\n")                                                               # edit_file
    env.push("3 passed in 0.5s\n", returncode=0)                                   # run_tests
    client = FakeClient(
        message(text("Reading."), tool_use("read_file", path="pkg/fetch.py"), usage=usage(100, 20)),
        message(tool_use("edit_file", path="pkg/fetch.py", old="requests.get(url)",
                         new="safe_fetch(url, allow_hosts=HOSTS)"), usage=usage(200, 30, cr=50)),
        message(tool_use("run_tests"), usage=usage(300, 40, cw=10)),
        message(tool_use("write_report", report=GOOD_REPORT), usage=usage(400, 60)),
    )
    res = run(client, env)

    assert res.stop_reason == STOP_DONE and res.failure_reason == ""
    assert res.report == GOOD_REPORT
    assert res.tool_calls == 4 and res.denials == []
    assert res.usage == Usage(input_tokens=1000, output_tokens=150, cache_read_tokens=50, cache_write_tokens=10)
    assert res.cost_usd == pytest.approx((1000 * 0.10 + 150 * 0.50 + 50 * 0.01 + 10 * 0.125) / 1e6)
    assert res.cost_usd > 0 and res.model == "claude-haiku-5-5"
    assert len(client.requests) == 4                   # write_report ends it: no fifth turn

    # argv shapes, never shell strings
    assert env.calls[0][:2] == ["python", "-c"] and env.calls[0][-3:] == ["pkg/fetch.py", "1", "400"]
    assert env.calls[1][:2] == ["python", "-c"] and env.calls[1][-3:] == [
        "pkg/fetch.py", "requests.get(url)", "safe_fetch(url, allow_hosts=HOSTS)"]
    assert env.calls[2] == ["python", "-m", "pytest", "tests/security", "-q"]
    assert len(env.calls) == 3                         # write_report never touches the box

    # request shape (plain messages.stream for Haiku, no fallback kwargs)
    path, kw = client.requests[0]
    assert path == "messages"
    assert kw["model"] == "claude-haiku-5-5" and kw["max_tokens"] == 16000
    assert kw["system"] == "You are the egress agent."
    assert kw["thinking"] == {"type": "adaptive"} and kw["tool_choice"] == {"type": "auto"}
    assert [t["name"] for t in kw["tools"]] == list(TOOLS)
    assert "betas" not in kw and "fallbacks" not in kw
    prompt = kw["messages"][0]["content"]
    assert kw["messages"][0]["role"] == "user"
    assert "property P4" in prompt and str(tmp_path) in prompt and "demo" in prompt
    assert "write_report" in prompt and "run_tests" in prompt

    # conversation: assistant content appended verbatim, one user message of tool_results per turn
    _, kw4 = client.requests[3]
    msgs = kw4["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "user", "assistant", "user", "assistant", "user"]
    assert [b.type for b in msgs[1]["content"]] == ["text", "tool_use"]   # response.content verbatim
    first_results = msgs[2]["content"]
    assert len(first_results) == 1 and first_results[0]["type"] == "tool_result"
    assert first_results[0]["tool_use_id"] == msgs[1]["content"][1].id
    assert first_results[0]["is_error"] is False
    assert "requests.get(url)" in first_results[0]["content"]

    # transcript: names + sizes, truncated results
    assert [e["tool"] for e in res.transcript] == ["read_file", "edit_file", "run_tests", "write_report"]
    assert res.transcript[1]["args_summary"] == {
        "path": len("pkg/fetch.py"), "old": len("requests.get(url)"), "new": len("safe_fetch(url, allow_hosts=HOSTS)")}
    assert res.transcript[0]["result_chars"] > 0 and res.transcript[0]["is_error"] is False
    assert res.elapsed_s >= 0


def test_container_mode_prompt_says_work_and_run_tests_sends_container_test(tmp_path):
    env = FakeEnv(tmp_path, mode="container")
    client = FakeClient(message(tool_use("run_tests"), ),
                        message(text("done"), stop_reason="end_turn"))
    res = run(client, env)
    assert "/work" in client.requests[0][1]["messages"][0]["content"]
    assert env.calls == [["python", "-m", "pytest", "tests/security", "-q"]]
    assert res.stop_reason == STOP_DONE and res.failure_reason == "no report" and res.report is None


def test_parallel_tool_uses_answered_in_one_user_message(tmp_path):
    env = FakeEnv(tmp_path)
    env.push("./a.py\n./b.py\n")
    env.push("a.py:1:import requests\n")
    client = FakeClient(
        message(tool_use("list_files"), tool_use("grep", pattern="requests")),
        message(text("ok"), stop_reason="end_turn"),
    )
    res = run(client, env)
    msgs = client.requests[1][1]["messages"]
    assert [m["role"] for m in msgs] == ["user", "assistant", "user"]
    assert [r["type"] for r in msgs[2]["content"]] == ["tool_result", "tool_result"]
    assert res.tool_calls == 2
    assert env.calls[0] == ["find", ".", "-maxdepth", "3", "-not", "-path", "*/.git/*"]
    assert env.calls[1] == ["grep", "-rn", "--include=*.py", "-e", "requests", "."]


def test_grep_no_match_is_not_an_error_and_pattern_is_an_argv_item(tmp_path):
    env = FakeEnv(tmp_path)
    env.push("", returncode=1)
    client = FakeClient(message(tool_use("grep", pattern="-x; rm -rf /", path="pkg")),
                        message(stop_reason="end_turn"))
    run(client, env)
    assert env.calls[0] == ["grep", "-rn", "--include=*.py", "-e", "-x; rm -rf /", "pkg"]
    result = client.requests[1][1]["messages"][2]["content"][0]
    assert result["is_error"] is False and result["content"] == "no matches"


def test_list_files_capped_at_400_lines(tmp_path):
    env = FakeEnv(tmp_path)
    env.push("\n".join(f"./f{i}.py" for i in range(1000)))
    client = FakeClient(message(tool_use("list_files", path=".")), message(stop_reason="end_turn"))
    run(client, env)
    content = client.requests[1][1]["messages"][2]["content"][0]["content"]
    assert content.count("\n") <= 401 and "truncated" in content


def test_edit_rejected_is_an_error_result_not_a_denial(tmp_path):
    env = FakeEnv(tmp_path)
    env.push("edit_rejected: old occurs 2 times (must be exactly 1)\n", returncode=3)
    client = FakeClient(message(tool_use("edit_file", path="a.py", old="x", new="y")),
                        message(stop_reason="end_turn"))
    res = run(client, env)
    result = client.requests[1][1]["messages"][2]["content"][0]
    assert result["is_error"] is True and "edit_rejected" in result["content"]
    assert res.denials == [] and res.tool_calls == 1


def test_run_tests_failure_is_reported_with_exit_code(tmp_path):
    env = FakeEnv(tmp_path)
    env.push("FAILED tests/security/test_x.py::t\n", returncode=1)
    client = FakeClient(message(tool_use("run_tests")), message(stop_reason="end_turn"))
    run(client, env)
    result = client.requests[1][1]["messages"][2]["content"][0]
    assert result["content"].startswith("exit 1\n") and "FAILED" in result["content"]


# --------------------------------------------------------------------- denials

@pytest.mark.parametrize("bad", ["../x", "/etc/passwd", "a/../../b", "pkg/..", "~/x"])
def test_path_escape_denied(tmp_path, bad):
    env = FakeEnv(tmp_path)
    client = FakeClient(message(tool_use("read_file", path=bad)), message(stop_reason="end_turn"))
    res = run(client, env)
    assert env.calls == []
    assert [d.reason for d in res.denials] == ["path_escape"]
    assert res.denials[0].tool == "read_file" and res.denials[0].call_index == 1
    result = client.requests[1][1]["messages"][2]["content"][0]
    assert result["is_error"] is True and "path_escape" in result["content"]
    assert res.tool_calls == 1


def test_path_escape_applies_to_every_path_argument(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(
        message(tool_use("list_files", path="../"), tool_use("grep", pattern="x", path="/"),
                tool_use("edit_file", path="../../a", old="a", new="b")),
        message(stop_reason="end_turn"),
    )
    res = run(client, env)
    assert env.calls == []
    assert [d.reason for d in res.denials] == ["path_escape"] * 3
    assert [d.tool for d in res.denials] == ["list_files", "grep", "edit_file"]


def test_normal_relative_paths_pass(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(message(tool_use("read_file", path="./pkg/../pkg/fetch.py")),
                        message(stop_reason="end_turn"))
    # `..` segments are denied even when they normalize inside the root (contract: any `..`)
    res = run(client, env)
    assert [d.reason for d in res.denials] == ["path_escape"]
    env2 = FakeEnv(tmp_path)
    client2 = FakeClient(message(tool_use("read_file", path="./pkg/fetch.py")),
                         message(stop_reason="end_turn"))
    res2 = run(client2, env2)
    assert res2.denials == [] and env2.calls[0][-3] == "pkg/fetch.py"


def test_unknown_tool_denied(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(message(tool_use("bash", command="ls")), message(stop_reason="end_turn"))
    res = run(client, env)
    assert env.calls == []
    assert [(d.tool, d.reason) for d in res.denials] == [("bash", "unknown_tool")]
    result = client.requests[1][1]["messages"][2]["content"][0]
    assert result["is_error"] is True
    assert res.tool_calls == 1


def test_bad_args_denied(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(
        message(tool_use("read_file", start=1),                    # missing path
                tool_use("read_file", path="a.py", start="1"),       # wrong type
                tool_use("edit_file", path="a.py", old="", new="x"),  # empty old
                tool_use("grep", pattern="x", extra=1)),              # unexpected key
        message(stop_reason="end_turn"),
    )
    res = run(client, env)
    assert env.calls == []
    assert [d.reason for d in res.denials] == ["bad_args"] * 4


def test_run_tests_ignores_arguments(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(message(tool_use("run_tests", cmd="rm -rf /")), message(stop_reason="end_turn"))
    res = run(client, env)
    assert env.calls == [["python", "-m", "pytest", "tests/security", "-q"]]
    assert res.denials == []


# --------------------------------------------------------------------- report validation

@pytest.mark.parametrize("mutate, key", [
    (lambda r: r.pop("claims"), "claims"),
    (lambda r: r.__setitem__("property", "PX"), "property"),
    (lambda r: r["findings"][0].__setitem__("line", "12"), "findings[0].line"),
    (lambda r: r["findings"][0].__setitem__("status", "done"), "findings[0].status"),
    (lambda r: r["findings"][0].__setitem__("severity", "critical"), "findings[0].severity"),
    (lambda r: r["claims"][0].pop("oracle"), "claims[0].oracle"),
    (lambda r: r.__setitem__("findings", {}), "findings"),
    (lambda r: r["findings"][0].__setitem__("line", True), "findings[0].line"),
])
def test_invalid_report_denied_and_not_stored(tmp_path, mutate, key):
    bad = json.loads(json.dumps(GOOD_REPORT))
    mutate(bad)
    assert validate_report(bad) and validate_report(bad).startswith(key)
    env = FakeEnv(tmp_path)
    client = FakeClient(message(tool_use("write_report", report=bad)), message(stop_reason="end_turn"))
    res = run(client, env)
    assert res.report is None
    assert [d.reason for d in res.denials] == ["invalid_report"]
    assert key in res.denials[0].detail
    result = client.requests[1][1]["messages"][2]["content"][0]
    assert result["is_error"] is True and key in result["content"]
    assert res.stop_reason == STOP_DONE and res.failure_reason == "no report"


def test_validate_report_accepts_good_and_minimal():
    assert validate_report(GOOD_REPORT) is None
    assert validate_report({"agent": "a", "property": "P0", "repo": "r", "commit": "c",
                            "findings": [], "claims": []}) is None
    assert validate_report("nope") == "report: expected object"


def test_model_can_retry_after_invalid_report(tmp_path):
    bad = {k: v for k, v in GOOD_REPORT.items() if k != "claims"}
    client = FakeClient(message(tool_use("write_report", report=bad)),
                        message(tool_use("write_report", report=GOOD_REPORT)))
    res = run(client, FakeEnv(tmp_path))
    assert res.stop_reason == STOP_DONE and res.report == GOOD_REPORT
    assert [d.reason for d in res.denials] == ["invalid_report"] and res.tool_calls == 2


# --------------------------------------------------------------------- stop reasons

def test_refusal_stops_without_running_tools(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(message(tool_use("run_tests"), stop_reason="refusal"))
    res = run(client, env)
    assert res.stop_reason == STOP_REFUSAL and env.calls == [] and res.tool_calls == 0
    assert res.usage.total == 150


def test_max_tokens_with_tool_use_is_an_error(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(message(tool_use("edit_file", path="a.py", old="x", new="y"), stop_reason="max_tokens"))
    res = run(client, env)
    assert res.stop_reason == STOP_ERROR and res.failure_reason == "tool input truncated"
    assert env.calls == []


def test_max_tokens_text_only_is_done_without_report(tmp_path):
    client = FakeClient(message(text("...long"), stop_reason="max_tokens"))
    res = run(client, FakeEnv(tmp_path))
    assert res.stop_reason == STOP_DONE and res.failure_reason == "no report"


def test_budget_trips_after_n_tool_turns(tmp_path):
    env = FakeEnv(tmp_path)
    script = [message(tool_use("list_files")) for _ in range(10)]
    client = FakeClient(*script)
    res = run(client, env, max_tool_calls=3)
    assert res.stop_reason == STOP_BUDGET and res.failure_reason.startswith("budget:")
    assert "4 tool calls" in res.failure_reason
    assert res.tool_calls == 4 and len(client.requests) == 4


def test_budget_trips_mid_batch(tmp_path):
    env = FakeEnv(tmp_path)
    client = FakeClient(message(*[tool_use("list_files") for _ in range(5)]))
    res = run(client, env, max_tool_calls=2)
    assert res.stop_reason == STOP_BUDGET and res.tool_calls == 3 and len(env.calls) == 3


def test_budget_trips_on_tokens(tmp_path):
    client = FakeClient(message(tool_use("list_files"), usage=usage(400_000, 1000)),
                        message(tool_use("list_files"), usage=usage(99_000, 1)))
    res = run(client, FakeEnv(tmp_path))
    assert res.stop_reason == STOP_BUDGET and "tokens" in res.failure_reason
    assert res.tool_calls == 1                       # the second turn's tool never ran
    assert res.usage.total == 500_001


def test_budget_trips_on_usd(tmp_path):
    # Opus: 25k input tokens = $0.10 per turn; 75k tokens total stays far under the token guard
    client = FakeClient(message(tool_use("list_files"), usage=usage(25_000, 0)),
                        message(tool_use("list_files"), usage=usage(25_000, 0)),
                        message(tool_use("list_files"), usage=usage(25_000, 0)))
    res = run(client, FakeEnv(tmp_path), model="claude-opus-5-5", budget=0.25)
    assert res.stop_reason == STOP_BUDGET and res.failure_reason.startswith("budget: $")
    assert len(client.requests) == 3 and res.cost_usd == pytest.approx(0.30)
    assert res.tool_calls == 2                       # the third turn's tool never ran


def test_unparseable_tool_json_reissues_turn_then_errors(tmp_path):
    client = FakeClient(ValueError("Unable to parse tool parameter JSON from model"),
                        message(tool_use("list_files")),
                        message(stop_reason="end_turn"))
    res = run(client, FakeEnv(tmp_path))
    assert res.stop_reason == STOP_DONE and res.tool_calls == 1
    assert [d.reason for d in res.denials] == ["bad_args"]
    assert len(client.requests) == 3
    assert client.requests[1][1]["messages"] == client.requests[0][1]["messages"]

    client2 = FakeClient(ValueError("x"), ValueError("y"), ValueError("z"), message(stop_reason="end_turn"))
    res2 = run(client2, FakeEnv(tmp_path))
    assert res2.stop_reason == STOP_ERROR and "unparseable" in res2.failure_reason
    assert len(client2.requests) == 3 and len(res2.denials) == 3


def test_api_error_reports_class_and_redacted_message(tmp_path):
    anthropic = pytest.importorskip("anthropic")
    import httpx
    req = httpx.Request("POST", "https://api.invalid/v1/messages")
    err = anthropic.AuthenticationError("invalid x-api-key sk-ant-SECRET", response=httpx.Response(401, request=req),
                                        body=None)
    res = run(FakeClient(err), FakeEnv(tmp_path))
    assert res.failure_reason.startswith('api: AuthenticationError: invalid x-api-key') and '[redacted-secret]' in res.failure_reason
    assert "sk-ant" not in res.failure_reason


def test_non_api_exceptions_propagate(tmp_path):
    with pytest.raises(RuntimeError):
        run(FakeClient(RuntimeError("boom")), FakeEnv(tmp_path))


# --------------------------------------------------------------------- fallback kwargs

@pytest.mark.parametrize("model", ["claude-opus-5-5", "claude-sonnet-5-5"])
def test_fallback_models_use_beta_stream_with_fallbacks(tmp_path, model):
    client = FakeClient(message(stop_reason="end_turn"))
    run(client, FakeEnv(tmp_path), model=model)
    path, kw = client.requests[0]
    assert path == "beta.messages"
    assert kw["betas"] == ["server-side-fallback-2026-07-01"] and kw["fallbacks"] == "default"
    assert kw["thinking"] == {"type": "adaptive"} and kw["max_tokens"] == 16000


def test_haiku_has_no_fallback_kwargs(tmp_path):
    client = FakeClient(message(stop_reason="end_turn"))
    run(client, FakeEnv(tmp_path), model="claude-haiku-5-5")
    path, kw = client.requests[0]
    assert path == "messages" and "betas" not in kw and "fallbacks" not in kw


def test_fallback_model_set_is_exactly_the_contract_list():
    assert loop.FALLBACK_MODELS == {"claude-opus-5-5", "claude-sonnet-5-5", "claude-opus-5", "claude-fable-5-1"}


# --------------------------------------------------------------------- safety

def test_run_trial_requires_a_model(tmp_path):
    with pytest.raises(ValueError):
        run(FakeClient(), FakeEnv(tmp_path), model="")
    with pytest.raises(ValueError):
        run(FakeClient(), FakeEnv(tmp_path), model=None)
    assert "DEFAULT_MODEL" not in open(loop.__file__).read()


def test_transcript_redacts_secret_shapes(tmp_path):
    env = FakeEnv(tmp_path)
    env.push(f"1\tKEY = '{PLANTED}'\n2\tAWS = 'AKIAIOSFODNN7EXAMPLE'\n3\t-----BEGIN RSA PRIVATE KEY-----\n")
    client = FakeClient(message(tool_use("read_file", path="cfg.py")),
                        message(stop_reason="end_turn"))
    res = run(client, env)
    dumped = json.dumps(res.transcript)
    assert PLANTED not in dumped and "AKIAIOSFODNN7EXAMPLE" not in dumped and "PRIVATE KEY" not in dumped
    assert "[redacted]" in dumped
    # the model still sees the real tool output (it is inside the box; the agent must read it)
    assert PLANTED in client.requests[1][1]["messages"][2]["content"][0]["content"]


def test_transcript_truncates_results_to_2kb_and_keeps_only_sizes(tmp_path):
    env = FakeEnv(tmp_path)
    env.push("x" * 10_000)
    client = FakeClient(message(tool_use("edit_file", path="a.py", old="secret-old", new="n")),
                        message(stop_reason="end_turn"))
    res = run(client, env)
    entry = res.transcript[0]
    assert set(entry) >= {"turn", "tool", "args_summary", "result_chars", "is_error"}
    assert len(entry["result"]) <= 2048 and entry["result_chars"] == 10_000
    assert "secret-old" not in json.dumps(entry["args_summary"])
    assert entry["args_summary"] == {"path": 4, "old": 10, "new": 1}


def test_log_callable_receives_progress_lines(tmp_path):
    lines = []
    client = FakeClient(message(tool_use("list_files")), message(stop_reason="end_turn"))
    run(client, FakeEnv(tmp_path), log=lines.append)
    assert any("turn 1" in l for l in lines) and any("list_files" in l for l in lines)
    assert any(l.startswith("stop=done") for l in lines)


def test_loop_module_imports_without_anthropic(monkeypatch):
    import importlib, sys
    monkeypatch.setitem(sys.modules, "anthropic", None)   # import would raise ImportError
    mod = importlib.reload(loop)
    assert callable(mod.run_trial)
    assert mod._api_error_type() == ()
    monkeypatch.undo()
    importlib.reload(loop)


def test_every_tool_schema_is_strict_at_every_object_level():
    """The API rejected write_report's nested object without additionalProperties:false."""
    from evals.agent import loop as L
    def strict(sch):
        if isinstance(sch, dict):
            if sch.get("type") == "object" and sch.get("additionalProperties") is not False:
                return False
            return all(strict(v) for v in sch.values())
        if isinstance(sch, list):
            return all(strict(x) for x in sch)
        return True
    for t in L.tool_definitions():
        assert strict(t["input_schema"]), t["name"]


def test_is_config_error_classifies_request_and_credential_faults():
    from evals.agent import loop as L
    assert L.is_config_error("api: BadRequestError: tools.5.custom ...")
    assert L.is_config_error("api: AuthenticationError: invalid x-api-key")
    assert not L.is_config_error("api: RateLimitError: slow down")
    assert not L.is_config_error("budget: 40 tool calls (max 40)")
