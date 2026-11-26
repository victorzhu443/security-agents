import subprocess
import sys
from pathlib import Path

from secprim import child_env


def run_untrusted(code: str, workdir: Path) -> subprocess.CompletedProcess:
    """Same runner; the child sees only the allow-listed keys (PATH, locale, TZ)."""
    return subprocess.run([sys.executable, "-c", code], cwd=workdir, env=child_env(),
                          capture_output=True, text=True, timeout=30)
