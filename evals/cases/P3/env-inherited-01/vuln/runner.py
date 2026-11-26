import subprocess
import sys
from pathlib import Path


def run_untrusted(code: str, workdir: Path) -> subprocess.CompletedProcess:
    """Runs model-authored code in its own process and directory — but env=None
    hands the child every variable the orchestrator holds."""
    return subprocess.run([sys.executable, "-c", code], cwd=workdir,
                          capture_output=True, text=True, timeout=30)
