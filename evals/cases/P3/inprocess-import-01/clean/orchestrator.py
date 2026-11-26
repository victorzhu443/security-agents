import json
import subprocess
import sys
import uuid
from pathlib import Path

from secprim import child_env


class Orchestrator:
    def __init__(self, work: Path):
        self.work = Path(work)

    def call(self, module: str, fn: str, kwargs: dict) -> dict:
        """Sandbox.call(): module.fn(**kwargs) runs in a child in the work dir; JSON in, JSON out."""
        call_id = uuid.uuid4().hex[:12]
        call_file, result_file = self.work / f"_call_{call_id}.json", self.work / f"_result_{call_id}.json"
        call_file.write_text(json.dumps({"id": call_id, "module": module, "fn": fn, "kwargs": kwargs}))
        subprocess.run([sys.executable, "_runner.py", call_file.name], cwd=self.work,
                       env=child_env(set={"PYTHONPATH": str(self.work)}),
                       capture_output=True, text=True, timeout=300, check=True)
        return json.loads(result_file.read_text())["result"]

    def run_fn(self, cfg: dict, seed: int) -> dict:
        return self.call("pipeline", "run", {"cfg": cfg, "seed": seed})
