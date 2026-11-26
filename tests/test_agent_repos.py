"""The repo registry and clone plumbing of the agent harness (evals/agent/repos.py).

Only read-only git against a tiny fixture repo in tmp_path; the real project repos are
touched by one skip-if-absent test that does `git show` (no working-tree access)."""
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from evals.agent import repos
from evals.agent.repos import RepoConfig, catalogue_text, clone_at, load_repos, select_repos

GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, env=GIT_ENV).stdout.strip()


@pytest.fixture
def fixture_repo(tmp_path: Path):
    """A repo with two commits; the catalogue exists only at the second."""
    src = tmp_path / "src"
    (src / "security").mkdir(parents=True)
    (src / "mod.py").write_text("X = 1\n")
    _git(src, "init", "-q")
    _git(src, "add", "-A")
    _git(src, "commit", "-q", "-m", "one")
    first = _git(src, "rev-parse", "HEAD")
    (src / "security" / "mutations.yaml").write_text("test: python -m pytest\nmutations: []\n")
    _git(src, "add", "-A")
    _git(src, "commit", "-q", "-m", "two")
    second = _git(src, "rev-parse", "HEAD")
    # a third commit so HEAD != the pinned commit (the harness must not use HEAD)
    (src / "mod.py").write_text("X = 2\n")
    _git(src, "commit", "-q", "-am", "three")
    return src, first, second


def _cfg(src: Path, commit: str, local_path: str = "fx") -> RepoConfig:
    return RepoConfig(name="fx", url=str(src), local_path=local_path, commit=commit)


def test_load_repos_reads_the_four_pinned_repos():
    r = load_repos()
    assert set(r) == {"research-replication-agent", "smart-dispatch", "firstplay-backend", "study-hub"}
    for cfg in r.values():
        assert len(cfg.commit) == 40 and cfg.url.startswith("https://github.com/victorzhu443/")
        assert cfg.catalogue == "security/mutations.yaml"
        assert cfg.image_install and cfg.image_hash_files
    assert r["study-hub"].visibility == "private"


def test_select_repos_all_and_names_and_typo():
    r = load_repos()
    assert [c.name for c in select_repos("all", r)] == list(r)
    assert [c.name for c in select_repos("study-hub,smart-dispatch", r)] == ["study-hub", "smart-dispatch"]
    with pytest.raises(ValueError, match="unknown repo"):
        select_repos("study_hub", r)


def test_clone_at_checks_out_the_pinned_commit_not_head(fixture_repo, tmp_path, monkeypatch):
    src, first, second = fixture_repo
    monkeypatch.setenv("SA_REPOS_ROOT", str(tmp_path / "nowhere"))     # no local checkout -> url
    dest = clone_at(_cfg(src, second), tmp_path / "clone")
    assert _git(dest, "rev-parse", "HEAD") == second
    assert (dest / "security" / "mutations.yaml").is_file()
    assert (dest / "mod.py").read_text() == "X = 1\n"
    assert _git(src, "status", "--porcelain") == ""                   # the source is untouched


def test_clone_at_prefers_the_local_checkout(fixture_repo, tmp_path, monkeypatch):
    src, first, second = fixture_repo
    monkeypatch.setenv("SA_REPOS_ROOT", str(src.parent))
    cfg = RepoConfig(name="fx", url="https://example.invalid/none.git", local_path=src.name, commit=first)
    assert repos.local_checkout(cfg) == src
    dest = clone_at(cfg, tmp_path / "clone2")                          # the url is unreachable; must use src
    assert _git(dest, "rev-parse", "HEAD") == first
    assert not (dest / "security" / "mutations.yaml").exists()


def test_catalogue_text_reads_the_pinned_commit_object(fixture_repo, tmp_path, monkeypatch):
    src, first, second = fixture_repo
    monkeypatch.setenv("SA_REPOS_ROOT", str(src.parent))
    cfg = RepoConfig(name="fx", url=str(src), local_path=src.name, commit=second)
    assert yaml.safe_load(catalogue_text(cfg))["test"] == "python -m pytest"
    # the working tree is edited after the pin: the harness must not see it
    (src / "security" / "mutations.yaml").write_text("test: TAMPERED\nmutations: []\n")
    assert "TAMPERED" not in catalogue_text(cfg)
    _git(src, "checkout", "--", "security/mutations.yaml")


def test_catalogue_text_falls_back_to_a_cached_clone(fixture_repo, tmp_path, monkeypatch):
    src, first, second = fixture_repo
    monkeypatch.setenv("SA_REPOS_ROOT", str(tmp_path / "nowhere"))
    cache = tmp_path / "cache"
    text = catalogue_text(_cfg(src, second), cache_dir=cache)
    assert "mutations" in text and (cache / "fx" / ".git").exists()
    assert catalogue_text(_cfg(src, second), cache_dir=cache) == text   # second call reuses it


@pytest.mark.skipif(not (Path.home() / "Developer/projects/research-replication-agent/.git").exists(),
                    reason="local project checkouts absent")
def test_real_catalogues_resolve_at_their_pinned_commits():
    counts = {}
    for name, cfg in load_repos().items():
        data = yaml.safe_load(catalogue_text(cfg))
        counts[name] = len(data["mutations"])
    assert counts == {"research-replication-agent": 18, "smart-dispatch": 17,
                      "firstplay-backend": 11, "study-hub": 11}
