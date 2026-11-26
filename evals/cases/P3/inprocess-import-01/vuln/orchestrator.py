import importlib.util
import sys
from pathlib import Path


class Orchestrator:
    def __init__(self, work: Path):
        self.work = Path(work)

    def _load_pipeline(self):
        p = self.work / "pipeline.py"
        if not p.exists():
            raise RuntimeError("pipeline.py not found in work dir")
        spec_ = importlib.util.spec_from_file_location("pipeline", p)
        mod = importlib.util.module_from_spec(spec_)
        sys.path.insert(0, str(self.work))
        spec_.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod

    def run_fn(self, cfg: dict, seed: int) -> dict:
        return self._load_pipeline().run(cfg, seed)
