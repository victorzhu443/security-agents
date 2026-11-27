"""Repo registry and clone plumbing shared by env.py and tasks.py (owned by the integrator).

    load_repos()                 -> {name: RepoConfig} from evals/agent/repos.yaml
    local_checkout(cfg)          -> Path of the local checkout, or None (CI)
    catalogue_text(cfg)          -> the security/mutations.yaml text AT THE PINNED COMMIT
    clone_at(cfg, dest)          -> fresh clone of the repo at the pinned commit in `dest`

The project repos are only ever read (`git show`, `git clone`); nothing runs in them and
nothing is written to them. Clones come from the local checkout when it exists (fast, and
works for the one private repo) and from `url` otherwise.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

REPO = Path(__file__).resolve().parents[2]
REPOS_FILE = Path(__file__).with_name("repos.yaml")
DEFAULT_REPOS_ROOT = Path.home() / "Developer" / "projects"


@dataclass(frozen=True)
class RepoConfig:
    name: str
    url: str
    local_path: str
    commit: str
    catalogue: str = "security/mutations.yaml"
    visibility: str = "public"
    image_hash_files: List[str] = field(default_factory=list)
    image_install: List[str] = field(default_factory=list)
    base_image: str = "python:3.12-slim"      # `image.base` in repos.yaml; env.dockerfile/requirements_hash read it


def repos_root() -> Path:
    return Path(os.environ.get("SA_REPOS_ROOT", str(DEFAULT_REPOS_ROOT))).expanduser()


def load_repos(path: Path = REPOS_FILE) -> Dict[str, RepoConfig]:
    data = yaml.safe_load(path.read_text()) or {}
    out: Dict[str, RepoConfig] = {}
    for name, r in (data.get("repos") or {}).items():
        img = r.get("image") or {}
        out[name] = RepoConfig(name=name, url=r["url"], local_path=r["local_path"],
                               commit=str(r["commit"]), catalogue=r.get("catalogue", "security/mutations.yaml"),
                               visibility=r.get("visibility", "public"),
                               image_hash_files=list(img.get("hash_files", [])),
                               image_install=list(img.get("install", [])),
                               base_image=str(img.get("base", "python:3.12-slim")))
    return out


def select_repos(selector: str, repos: Optional[Dict[str, RepoConfig]] = None) -> List[RepoConfig]:
    """`all` or a comma-separated list of names; unknown names raise (a typo must not run nothing)."""
    repos = repos if repos is not None else load_repos()
    if selector == "all":
        return list(repos.values())
    out = []
    for n in selector.split(","):
        n = n.strip()
        if n not in repos:
            raise ValueError(f"unknown repo {n!r}; known: {', '.join(repos)}")
        out.append(repos[n])
    return out


def _git(*args: str, cwd: Optional[Path] = None, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd) if cwd else None, capture_output=True,
                          text=True, check=check, timeout=timeout)


def local_checkout(cfg: RepoConfig) -> Optional[Path]:
    p = repos_root() / cfg.local_path
    return p if (p / ".git").exists() else None


def _has_commit(repo: Path, sha: str) -> bool:
    return _git("cat-file", "-e", f"{sha}^{{commit}}", cwd=repo, check=False).returncode == 0


def clone_at(cfg: RepoConfig, dest: Path) -> Path:
    """Fresh detached clone of the repo at `cfg.commit` in `dest` (created). The source is
    the local checkout when present (its objects, never its working tree), else `url`."""
    src = local_checkout(cfg)
    source = str(src) if src is not None and _has_commit(src, cfg.commit) else cfg.url
    dest.parent.mkdir(parents=True, exist_ok=True)
    _git("clone", "--quiet", "--no-checkout", source, str(dest))
    if not _has_commit(dest, cfg.commit):
        _git("fetch", "--quiet", "origin", cfg.commit, cwd=dest)
    _git("checkout", "--quiet", "--detach", cfg.commit, cwd=dest)
    return dest


def catalogue_text(cfg: RepoConfig, cache_dir: Optional[Path] = None) -> str:
    """The catalogue as it is at the pinned commit. From the local checkout's objects when
    possible; otherwise from a clone cached under `cache_dir` (default: a temp dir kept per
    process). Never reads the local checkout's working tree."""
    src = local_checkout(cfg)
    if src is not None and _has_commit(src, cfg.commit):
        return _git("show", f"{cfg.commit}:{cfg.catalogue}", cwd=src).stdout
    cache_dir = cache_dir or Path(os.environ.get("SA_CLONE_CACHE", str(Path.home() / ".cache" / "security-agents" / "repos")))
    dest = cache_dir / cfg.name
    if not (dest / ".git").exists():
        clone_at(cfg, dest)
    elif not _has_commit(dest, cfg.commit):
        _git("fetch", "--quiet", "origin", cfg.commit, cwd=dest)
    return _git("show", f"{cfg.commit}:{cfg.catalogue}", cwd=dest).stdout
