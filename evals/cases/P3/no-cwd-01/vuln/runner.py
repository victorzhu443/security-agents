import subprocess
import sys
from pathlib import Path

from secprim import child_env


def run_untrusted(code: str, workdir: Path) -> subprocess.CompletedProcess:
    script = Path(workdir) / "main.py"
    script.write_text(code)
    # absolute script path, env allow-listed — but the child inherits OUR cwd
    return subprocess.run([sys.executable, str(script)], env=child_env(),
                          capture_output=True, text=True, timeout=30)
