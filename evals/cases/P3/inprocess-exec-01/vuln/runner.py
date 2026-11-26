import contextlib
import io
import subprocess
from pathlib import Path


def run_untrusted(code: str, workdir: Path) -> subprocess.CompletedProcess:
    """'Lightweight' execution: no process spawn, just capture prints."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(compile(code, str(Path(workdir) / "snippet.py"), "exec"), {"__name__": "__main__"})
    return subprocess.CompletedProcess(["<in-process>"], 0, buf.getvalue(), "")
