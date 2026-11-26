import json
import subprocess
import sys
from pathlib import Path

from secprim import child_env


def run_pipeline(workdir: Path, cfg: dict) -> dict:
    workdir = Path(workdir)
    (workdir / "_call.json").write_text(json.dumps(cfg))
    subprocess.run([sys.executable, "pipeline.py", "_call.json"], cwd=workdir, env=child_env(),
                   capture_output=True, text=True, timeout=300, check=True)
    return json.loads((workdir / "_result.json").read_text())
