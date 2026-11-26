import subprocess
import sys
from pathlib import Path

from secprim import child_env

SANDBOX_ALLOW = frozenset({"PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "HF_HOME"})


class Sandbox:
    """The one execution boundary for model-authored code. (The real Sandbox also
    picks a `docker run --network none --read-only` backend when the image exists;
    the local backend announces that network is not restricted.)"""

    def __init__(self, workdir: Path):
        self.workdir = Path(workdir)

    def run(self, argv, env=None, timeout_s: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(argv, cwd=self.workdir, env=child_env(allow=SANDBOX_ALLOW, set=env),
                              capture_output=True, text=True, timeout=timeout_s, start_new_session=True)


def run_tool(code: str, workdir: Path) -> subprocess.CompletedProcess:
    """The builder's run_python tool: through the boundary."""
    return Sandbox(workdir).run([sys.executable, "-c", code])


def run_reproduce(code: str, workdir: Path, seed: int = 0) -> subprocess.CompletedProcess:
    """The CS track's reproduce step: the same boundary as every other exec path."""
    workdir = Path(workdir)
    (workdir / "reproduce.py").write_text(code)
    return Sandbox(workdir).run([sys.executable, "reproduce.py"], env={"SEED": str(seed)})
