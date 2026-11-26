from pathlib import Path


def run_pipeline(workdir: Path, cfg: dict) -> dict:
    ns = {"__name__": "pipeline"}
    exec((Path(workdir) / "pipeline.py").read_text(), ns)   # foreign code, our process
    return ns["run"](cfg)
