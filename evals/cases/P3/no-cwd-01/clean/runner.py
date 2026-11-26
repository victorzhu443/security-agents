import subprocess
import sys
from pathlib import Path

from secprim import child_env


def run_untrusted(code: str, workdir: Path) -> subprocess.CompletedProcess:
    script = Path(workdir) / "main.py"
    script.write_text(code)
    # relative writes from the foreign code now land inside workdir
    return subprocess.run([sys.executable, "main.py"], cwd=workdir, env=child_env(),
                          capture_output=True, text=True, timeout=30)
