import os
import subprocess
import sys
from pathlib import Path

from secprim import child_env

SECRET_ENV_KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
SANDBOX_ALLOW = frozenset({"PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "HF_HOME"})


def scrub_secrets(env: dict) -> dict:
    """Copy of env with the orchestrator's LLM-provider credentials removed."""
    return {k: v for k, v in env.items() if k not in SECRET_ENV_KEYS}


class Sandbox:
    """The one execution boundary for model-authored code."""

    def __init__(self, workdir: Path):
        self.workdir = Path(workdir)

    def run(self, argv, env=None, timeout_s: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(argv, cwd=self.workdir, env=child_env(allow=SANDBOX_ALLOW, set=env),
                              capture_output=True, text=True, timeout=timeout_s, start_new_session=True)


def run_tool(code: str, workdir: Path) -> subprocess.CompletedProcess:
    """The builder's run_python tool: through the boundary."""
    return Sandbox(workdir).run([sys.executable, "-c", code])


def run_reproduce(code: str, workdir: Path, seed: int = 0) -> subprocess.CompletedProcess:
    """The CS track's reproduce step: its own Popen, around the boundary."""
    workdir = Path(workdir)
    (workdir / "reproduce.py").write_text(code)
    env = {**os.environ, "SEED": str(seed), "TOKENIZERS_PARALLELISM": "false"}
    env = scrub_secrets(env)          # drops the two named keys; everything else goes through
    proc = subprocess.Popen([sys.executable, "reproduce.py"], cwd=workdir, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    out, err = proc.communicate(timeout=30)
    return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)
