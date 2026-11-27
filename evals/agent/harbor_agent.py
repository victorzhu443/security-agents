"""Our security agent as a Harbor external agent (evals/calib Phase 1, W-C).

    harbor run -p evals/calib/egress/splits/train -a evals.agent.harbor_agent:SecurityAgent \
        -m anthropic/claude-sonnet-5-5 --ak condition=class-blind --ak budget_usd=0.50 -k 3 -n 4

`SecurityAgent` keeps OUR model loop (`evals.agent.loop.run_trial`: six argv tools, strict
schemas, `prices.yaml` cost, BudgetGuard) and runs it on the HOST, outside the box; every tool
reaches the sandbox through `HarborEnv`, a pure adapter from our `Env.exec(argv)` to Harbor's
`BaseEnvironment.exec(shell string, cwd=/app)` via `shlex.join`. The agent never reads `/tests`:
the task it builds comes from the instruction alone (repo = /app, suite command parsed from the
instruction's backticks). Harbor's `terminus_2` is the structural template (logs_dir, context
filled in a `finally`, trajectory dumped last); its LiteLLM wrapper is deliberately not used.

Spending: `budget_usd` (an `--ak`) is the per-trial cap for BudgetGuard; its default 0.0 means
"refuse" — `run` raises before any request, so a `harbor run` without `--ak budget_usd=…` spends
nothing. The model is required too (`-m`; loop refuses an unpriced one).

Outputs: `/logs/artifacts/report.json` (uploaded from a temp file; the separate verifier reads
it), `<logs_dir>/trajectory.json` (ATIF v1.8, `to_atif`), and `AgentContext` tokens / cost /
metadata (condition, stop reason, prompt hashes).

`SastAgent` (amendment A4) wraps a static analyser as a baseline: runs `--ak invocation=…` in
/app, downloads its output, converts it with `--ak adapter=module:function` (W-D's
`evals.calib.sast`, imported lazily) into a report, uploads it, writes a minimal trajectory.

The `harbor` imports are guarded: this module imports without harbor (unit tests never need it);
`HARBOR_AVAILABLE` says which case we are in.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import importlib
import inspect
import json
import logging
import os
import re
import shlex
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from ..calib import ATIF_SCHEMA_VERSION, EVAL_ID, LOGS_ARTIFACTS, PROPERTY, REPORT_ARTIFACT, TRAJECTORY_FILE, WORKDIR
from ..run import toolkit_version
from . import prompts
from .loop import run_trial, validate_report
from .types import (KIND_ADVISORY, SCOPE_REACHABLE_FROM_FIX, SOURCE_ADVISORY, STOP_ERROR, ExecResult, LoopResult,
                    Task, Usage)

try:  # pragma: no cover - exercised only where harbor is installed
    from harbor.agents.agent_auth_resolution import ModelConnectionSpec, ProviderAccess
    from harbor.agents.base import BaseAgent
    from harbor.agents.capabilities import AgentCapabilities
    from harbor.models.model_api_format import ModelApiFormat
    HARBOR_AVAILABLE = True
except ImportError:
    BaseAgent = object  # type: ignore[assignment,misc]
    HARBOR_AVAILABLE = False

AGENT_NAME = "security-agents"
SAST_AGENT_NAME = "security-agents-sast"
PROVIDER = "anthropic"
API_KEY_ENV: Sequence[str] = ("ANTHROPIC_API_KEY",)
API_FORMAT = "anthropic_messages"
DEFAULT_SUITE: Sequence[str] = ("python", "-m", "pytest", "tests", "-q", "-x", "-p", "no:cacheprovider")
EXEC_TIMEOUT_S = 600
SAST_TIMEOUT_S = 1800
#: The instruction names the suite as "test suite (`<argv>`)"; this finds it.
_SUITE_RE = re.compile(r"test suite \(`([^`]+)`\)")
_BACKTICK_RE = re.compile(r"`([^`]+)`")


def _model_connection():
    if not HARBOR_AVAILABLE:
        return None
    return ModelConnectionSpec(
        default_provider=PROVIDER,
        agent_provider_access=ProviderAccess(api_key_candidate_names=list(API_KEY_ENV)),
        supported_api_formats=[ModelApiFormat.ANTHROPIC_MESSAGES],
    )


def _capabilities():
    return AgentCapabilities(atif=True) if HARBOR_AVAILABLE else {"atif": True}


def bare_model_name(model_name: str) -> str:
    """`anthropic/claude-sonnet-5-5` -> `claude-sonnet-5-5` (prices.yaml keys bare ids)."""
    name = (model_name or "").strip()
    return name.split("/", 1)[1] if "/" in name else name


def suite_from_instruction(instruction: str) -> List[str]:
    """The project's suite argv from the instruction text, else DEFAULT_SUITE."""
    m = _SUITE_RE.search(instruction or "")
    candidates = [m.group(1)] if m else _BACKTICK_RE.findall(instruction or "")
    for text in candidates:
        try:
            argv = shlex.split(text)
        except ValueError:
            continue
        if argv and (argv[0] in ("pytest",) or argv[0].startswith("python")):
            return argv
    return list(DEFAULT_SUITE)


def task_from_instruction(instruction: str, *, agent_spec: str = "agents/egress.md",
                          workdir: str = WORKDIR) -> Task:
    """The Task the loop needs, from the instruction alone — the agent never sees tests/.
    `description` is empty by construction (never advisory text); `property` is the class
    this pipeline calibrates and is only ever used by the class-aware user text."""
    suite = suite_from_instruction(instruction)
    return Task(task_id="harbor", eval_id=EVAL_ID, repo=workdir, repo_url="", commit="HEAD",
                property=PROPERTY, description="", file="", find="", replace="",
                hidden_test=shlex.join(suite), suite_test=shlex.join(suite), container_test=list(suite),
                pythonpath=[], agent=agent_spec, canary="", source=SOURCE_ADVISORY,
                kind=KIND_ADVISORY, scope_rule=SCOPE_REACHABLE_FROM_FIX)


# --------------------------------------------------------------------- the environment adapter

class HarborEnv:
    """Our `Env` over a Harbor `BaseEnvironment`. Pure: tested with a fake environment.

    `exec(argv)` -> `environment.exec(shlex.join(argv), cwd=/app, timeout_sec=...)`; argv[0]
    `python` becomes `python3` (the task images guarantee `python3`). `environment.exec` is a
    coroutine: with `loop` set (the agent's running loop) it is submitted from the worker thread
    that runs our synchronous model loop; without one (tests) it is run to completion inline;
    a plain return value (a sync fake) is used as is."""
    mode = "harbor"

    def __init__(self, environment: Any, *, loop: Optional[asyncio.AbstractEventLoop] = None,
                 cwd: str = WORKDIR):
        self.environment = environment
        self.loop = loop
        self.cwd = cwd
        self.workdir = Path(cwd)
        self.calls: List[str] = []

    @staticmethod
    def command(argv: Sequence[str]) -> str:
        argv = [str(a) for a in argv]
        if argv and argv[0] == "python":
            argv[0] = "python3"
        return shlex.join(argv)

    def _await(self, value: Any, timeout_s: Optional[float] = None) -> Any:
        if not inspect.isawaitable(value):
            return value
        if self.loop is not None:
            fut = asyncio.run_coroutine_threadsafe(value, self.loop)
            try:
                return fut.result(None if timeout_s is None else timeout_s + 60)
            except concurrent.futures.TimeoutError:
                fut.cancel()
                raise TimeoutError(f"environment.exec did not return within {timeout_s}s")
        return asyncio.run(value)

    def exec(self, argv: Sequence[str], *, timeout_s: int = EXEC_TIMEOUT_S) -> ExecResult:
        cmd = self.command(argv)
        self.calls.append(cmd)
        t0 = time.monotonic()
        try:
            r = self._await(self.environment.exec(cmd, cwd=self.cwd, timeout_sec=timeout_s), timeout_s)
        except (asyncio.TimeoutError, TimeoutError):
            return ExecResult(124, "", f"timeout after {timeout_s}s", time.monotonic() - t0, timed_out=True)
        rc = getattr(r, "return_code", None)
        rc = int(rc) if isinstance(rc, int) else 1
        return ExecResult(rc, getattr(r, "stdout", "") or "", getattr(r, "stderr", "") or "",
                          time.monotonic() - t0, timed_out=(rc == 124))

    def reset(self, task: Task):
        raise NotImplementedError("HarborEnv: Harbor owns the sandbox; there is no reset")

    def diff(self) -> str:
        """The agent's edits (untracked files via `git add -N`); the verifier recomputes its own."""
        self.exec(["git", "add", "-N", "."])
        out = self.exec(["git", "diff", "--no-color"]).stdout
        self.exec(["git", "reset", "-q"])
        return out

    def close(self) -> None:
        pass


# --------------------------------------------------------------------- ATIF

def _arguments(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Tool arguments as the transcript keeps them: names + sizes, and the path when present
    (values are never recorded; see loop._args_summary)."""
    args: Dict[str, Any] = {"args_summary": dict(entry.get("args_summary") or {})}
    if isinstance(entry.get("path"), str):
        args["path"] = entry["path"]
    return args


def to_atif(lr: LoopResult, *, model: str, instruction: str, system: str,
            agent_version: Optional[str] = None) -> Dict[str, Any]:
    """An ATIF-v1.8 trajectory (harbor.models.trajectories) from a LoopResult: step 1 the
    system prompt, step 2 the user instruction, then one `agent` step per model turn with its
    tool calls and their observations (redacted, truncated results as the transcript holds
    them). Pure. Keys are exactly the pydantic models' (every one is `extra = "forbid"`)."""
    steps: List[Dict[str, Any]] = [
        {"step_id": 1, "source": "system", "message": system},
        {"step_id": 2, "source": "user", "message": instruction},
    ]
    turns: Dict[int, List[Dict[str, Any]]] = {}
    for entry in lr.transcript:
        turns.setdefault(int(entry.get("turn", 0)), []).append(entry)
    for turn in sorted(turns):
        entries = turns[turn]
        calls = [e for e in entries if e.get("tool")]
        step: Dict[str, Any] = {"step_id": len(steps) + 1, "source": "agent", "model_name": model}
        if calls:
            step["message"] = f"turn {turn}: {len(calls)} tool call(s)"
            step["tool_calls"] = []
            results = []
            for i, e in enumerate(calls, 1):
                call_id = f"call-{turn}-{i}"
                step["tool_calls"].append({"tool_call_id": call_id, "function_name": str(e["tool"]),
                                           "arguments": _arguments(e)})
                content = str(e.get("result", ""))
                if e.get("denial"):
                    content = f"[denied: {e['denial']}] {content}"
                results.append({"source_call_id": call_id, "content": content})
            step["observation"] = {"results": results}
        else:
            step["message"] = "; ".join(str(e.get("result", "")) for e in entries) or f"turn {turn}"
        steps.append(step)
    u: Usage = lr.usage
    return {
        "schema_version": ATIF_SCHEMA_VERSION,
        "agent": {"name": AGENT_NAME, "version": agent_version or toolkit_version(), "model_name": model,
                  "extra": {"loop": "evals.agent.loop.run_trial"}},
        "steps": steps,
        "final_metrics": {
            "total_prompt_tokens": u.input_tokens + u.cache_read_tokens + u.cache_write_tokens,
            "total_completion_tokens": u.output_tokens,
            "total_cached_tokens": u.cache_read_tokens,
            "total_cost_usd": float(lr.cost_usd),
            "total_steps": len(steps),
        },
        "extra": {"stop_reason": lr.stop_reason, "failure_reason": lr.failure_reason,
                  "tool_calls": lr.tool_calls, "denials": len(lr.denials),
                  "report_written": lr.report is not None, "elapsed_s": round(lr.elapsed_s, 3)},
    }


def minimal_atif(*, agent_name: str, version: str, instruction: str, tool: str,
                 arguments: Dict[str, Any], observation: str) -> Dict[str, Any]:
    """A two-step ATIF trajectory for a deterministic (non-LLM) agent such as SastAgent."""
    return {
        "schema_version": ATIF_SCHEMA_VERSION,
        "agent": {"name": agent_name, "version": version},
        "steps": [
            {"step_id": 1, "source": "user", "message": instruction},
            {"step_id": 2, "source": "agent", "message": f"run {tool}", "llm_call_count": 0,
             "tool_calls": [{"tool_call_id": "call-1-1", "function_name": tool, "arguments": arguments}],
             "observation": {"results": [{"source_call_id": "call-1-1", "content": observation}]}},
        ],
        "final_metrics": {"total_prompt_tokens": 0, "total_completion_tokens": 0, "total_cached_tokens": 0,
                          "total_cost_usd": 0.0, "total_steps": 2},
    }


# --------------------------------------------------------------------- shared agent plumbing

def _write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=False, default=str), encoding="utf-8")
    tmp.replace(path)


async def _upload_json(environment: Any, data: Dict[str, Any], target: str = REPORT_ARTIFACT) -> None:
    """Write `data` to a temp file and `upload_file` it to `target` (parent dir created first)."""
    fd, name = tempfile.mkstemp(prefix="sa-report-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        await _maybe_await(environment.exec(f"mkdir -p {shlex.quote(str(Path(target).parent))}"))
        await _maybe_await(environment.upload_file(name, target))
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _init_base(self, logs_dir, model_name, kwargs) -> None:
    """BaseAgent.__init__ when harbor is present; the two attributes it would set otherwise."""
    if HARBOR_AVAILABLE:
        BaseAgent.__init__(self, Path(logs_dir), model_name, **kwargs)  # type: ignore[misc]
    else:
        self.logs_dir = Path(logs_dir)
        self.model_name = model_name
        self.logger = logging.getLogger(__name__)


# --------------------------------------------------------------------- our agent

class SecurityAgent(BaseAgent):  # type: ignore[misc,valid-type]
    """`-a evals.agent.harbor_agent:SecurityAgent`; options via `--ak`:
    condition=class-blind|class-aware[+no_verifier], budget_usd=<per-trial cap, required>,
    agent_spec=agents/<name>.md (the class-aware spec)."""
    capabilities = _capabilities()
    MODEL_CONNECTION = _model_connection()

    def __init__(self, logs_dir, model_name: Optional[str] = None, *, condition: str = prompts.CLASS_BLIND,
                 budget_usd: float = 0.0, agent_spec: str = "agents/egress.md", **kwargs):
        _init_base(self, logs_dir, model_name, kwargs)
        self.condition = prompts.Condition.parse(condition)
        self.budget_usd = float(budget_usd)
        self.agent_spec = agent_spec
        self.repo_root = prompts.REPO
        self._client = None               # tests inject a fake Anthropic client here

    @staticmethod
    def name() -> str:
        return AGENT_NAME

    def version(self) -> str:
        return toolkit_version()

    async def setup(self, environment: Any) -> None:
        """Nothing to install: the loop runs on the host; the tools are `find`/`grep`/`git`/python3."""
        return None

    def _refuse_if_unfunded(self) -> None:
        if self.budget_usd <= 0:
            raise ValueError("SecurityAgent: budget_usd is 0 — refusing to run; pass `--ak budget_usd=<per-trial USD cap>`")
        if not self.model_name:
            raise ValueError("SecurityAgent: a model is required (`-m <provider>/<model>`); there is no default")

    def _prompts(self, task: Task, instruction: str) -> tuple[str, str]:
        system = prompts.system_body(task, self.condition, repo_root=self.repo_root)
        user = instruction.rstrip() + "\n\n" + prompts.user_text(task, self.condition, workdir=WORKDIR)
        return system, user

    async def run(self, instruction: str, environment: Any, context: Any) -> None:
        self._refuse_if_unfunded()
        model = bare_model_name(self.model_name)
        task = task_from_instruction(instruction, agent_spec=self.agent_spec)
        system, user = self._prompts(task, instruction)
        env = HarborEnv(environment, loop=asyncio.get_running_loop())
        log: Callable[[str], None] = self.logger.info
        t0 = time.monotonic()
        lr: Optional[LoopResult] = None
        report_written = False
        try:
            lr = await asyncio.to_thread(
                run_trial, task, env, model=model, budget_usd=self.budget_usd, agent_body=system,
                client=self._client, log=log, system_text=system, user_prompt_text=user)
            if lr.report is not None:
                await _upload_json(environment, lr.report, REPORT_ARTIFACT)
                report_written = True
        finally:
            if lr is None:
                lr = LoopResult(stop_reason=STOP_ERROR, report=None, tool_calls=0, denials=[], usage=Usage(),
                                cost_usd=0.0, model=model, failure_reason="harness: run_trial raised",
                                elapsed_s=time.monotonic() - t0)
            self._fill_context(context, lr, task, report_written)
            _write_json(Path(self.logs_dir) / TRAJECTORY_FILE,
                        to_atif(lr, model=model, instruction=user, system=system, agent_version=self.version()))

    def _fill_context(self, context: Any, lr: LoopResult, task: Task, report_written: bool) -> None:
        u = lr.usage
        context.n_input_tokens = u.input_tokens + u.cache_read_tokens + u.cache_write_tokens
        context.n_cache_tokens = u.cache_read_tokens
        context.n_output_tokens = u.output_tokens
        context.cost_usd = float(lr.cost_usd)
        context.metadata = {
            "agent_version": self.version(),
            "condition": self.condition.name,
            "passed_requires": list(self.condition.passed_requires),
            "stop_reason": lr.stop_reason,
            "failure_reason": lr.failure_reason,
            "tool_calls": lr.tool_calls,
            "denials": len(lr.denials),
            "report_written": report_written,
            "budget_usd": self.budget_usd,
            "prompt_hashes": prompts.prompt_hashes(task, self.condition, workdir=WORKDIR, repo_root=self.repo_root),
        }


# --------------------------------------------------------------------- SAST baseline wrapper

def output_path_of(invocation: str) -> str:
    """The output file an analyser invocation names (`-o X`, `--output X`, `--output=X`,
    `--output-file X`), or ""."""
    try:
        argv = shlex.split(invocation)
    except ValueError:
        return ""
    for i, tok in enumerate(argv):
        if tok in ("-o", "--output", "--output-file") and i + 1 < len(argv):
            return argv[i + 1]
        for flag in ("--output=", "--output-file="):
            if tok.startswith(flag):
                return tok[len(flag):]
    return ""


def resolve_adapter(spec: str) -> Callable[..., Dict[str, Any]]:
    """`module.path:function` -> the callable (imported lazily; W-D's adapters live in
    evals.calib.sast and must not be imported at module load)."""
    if ":" in spec:
        module_name, _, func_name = spec.partition(":")
    else:
        module_name, _, func_name = spec.rpartition(".")
    if not module_name or not func_name:
        raise ValueError(f"adapter must be `module.path:function`, got {spec!r}")
    module = importlib.import_module(module_name)
    fn = getattr(module, func_name, None)
    if not callable(fn):
        raise ValueError(f"adapter {spec!r}: {func_name!r} is not a callable in {module_name}")
    return fn


class SastAgent(BaseAgent):  # type: ignore[misc,valid-type]
    """`-a evals.agent.harbor_agent:SastAgent --ak invocation='semgrep scan … -o /tmp/out.json /app'
    --ak adapter=evals.calib.sast:semgrep_to_report --ak tool=semgrep [--ak output=/tmp/out.json]
    [--ak version=<tool pin>]`. No model, no key: a deterministic baseline graded by the same
    verifier (findings = reported locations; claims = [])."""
    capabilities = _capabilities()
    MODEL_CONNECTION = None

    def __init__(self, logs_dir, model_name: Optional[str] = None, *, invocation: str = "", adapter: str = "",
                 tool: str = "", output: str = "", version: str = "", timeout_s: int = SAST_TIMEOUT_S, **kwargs):
        _init_base(self, logs_dir, model_name, kwargs)
        self.invocation = invocation
        self.adapter = adapter
        self.tool = tool
        self.output = output or output_path_of(invocation)
        self.tool_version = version
        self.timeout_s = int(timeout_s)

    @staticmethod
    def name() -> str:
        return SAST_AGENT_NAME

    def version(self) -> str:
        return self.tool_version or toolkit_version()

    async def setup(self, environment: Any) -> None:
        return None

    def _check(self) -> Callable[..., Dict[str, Any]]:
        missing = [k for k, v in (("invocation", self.invocation), ("adapter", self.adapter), ("tool", self.tool)) if not v]
        if missing:
            raise ValueError(f"SastAgent: missing --ak {', '.join(missing)}")
        if not self.output:
            raise ValueError("SastAgent: the invocation names no output file; pass `--ak output=<path in the box>`")
        return resolve_adapter(self.adapter)

    async def run(self, instruction: str, environment: Any, context: Any) -> None:
        adapter = self._check()
        t0 = time.monotonic()
        r = await _maybe_await(environment.exec(self.invocation, cwd=WORKDIR, timeout_sec=self.timeout_s))
        rc = getattr(r, "return_code", None)
        rc = int(rc) if isinstance(rc, int) else 1
        observation = f"rc={rc}\n{(getattr(r, 'stdout', '') or '')[-2000:]}\n{(getattr(r, 'stderr', '') or '')[-2000:]}".rstrip()
        data: Any = None
        report: Optional[Dict[str, Any]] = None
        problem: Optional[str] = "no output"
        fd, name = tempfile.mkstemp(prefix="sa-sast-", suffix=".json")
        os.close(fd)
        try:
            try:
                await _maybe_await(environment.download_file(self.output, name))
                with open(name, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError) as e:
                problem = f"output unreadable: {type(e).__name__}"
            if data is not None:
                report = adapter(data, tool=self.tool)
                problem = validate_report(report)
                if problem is None:
                    await _upload_json(environment, report, REPORT_ARTIFACT)
        finally:
            try:
                os.unlink(name)
            except OSError:
                pass
            n_findings = len(report.get("findings", [])) if isinstance(report, dict) and problem is None else 0
            context.n_input_tokens = 0
            context.n_cache_tokens = 0
            context.n_output_tokens = 0
            context.cost_usd = 0.0
            context.metadata = {"agent_version": self.version(), "tool": self.tool, "invocation": self.invocation,
                                "adapter": self.adapter, "output": self.output, "rc": rc,
                                "report_valid": problem is None, "report_problem": problem or "",
                                "n_findings": n_findings, "elapsed_s": round(time.monotonic() - t0, 3)}
            _write_json(Path(self.logs_dir) / TRAJECTORY_FILE,
                        minimal_atif(agent_name=SAST_AGENT_NAME, version=self.version(), instruction=instruction,
                                     tool=self.tool, arguments={"invocation": self.invocation, "output": self.output},
                                     observation=observation))
