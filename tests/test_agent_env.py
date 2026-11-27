"""Tests of evals/agent/env.py: mode selection, the pure docker argv builders, the image
hash, a ContainerEnv.reset with every docker call recorded by a fake, and LocalEnv end to
end on a tiny git repo built in tmp_path. No docker, no network, no model; the only repo
anything clones is the fixture."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from evals.agent import env as envmod
from evals.agent.env import (ContainerEnv, LocalEnv, allowed_env, build_image, container_argv,
                             docker_available, dockerfile, exec_argv, image_tag, make_env,
                             requirements_hash)
from evals.agent.repos import RepoConfig
from evals.agent.types import Task

REAL_RUN = subprocess.run

MODULE = '''\
def allowed_host(host):
    return host in {"api.example.com"}
'''
TEST = '''\
from guard import allowed_host

def test_only_the_allow_listed_host_passes():
    assert allowed_host("api.example.com")
    assert not allowed_host("evil.example.com")
'''
FIND = 'host in {"api.example.com"}'
REPLACE = 'host.endswith("example.com")'
CATALOGUE = f'''\
test: "{sys.executable} -m pytest tests/security -q -x -p no:cacheprovider"
pythonpath: ["."]
mutations:
  - id: P4-host-suffix-match
    property: P4
    description: reintroduce the suffix match that let any example.com subdomain through
    file: guard.py
    find: '{FIND}'
    replace: '{REPLACE}'
'''


def _git(repo: Path, *args: str) -> str:
    return REAL_RUN(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                    env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                         "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                         "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "proj"
    (repo / "tests" / "security").mkdir(parents=True)
    (repo / "security").mkdir()
    (repo / "guard.py").write_text(MODULE)
    (repo / "tests" / "security" / "test_x.py").write_text(TEST)
    (repo / "security" / "mutations.yaml").write_text(CATALOGUE)
    (repo / "requirements.txt").write_text("pytest\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _cfg(repo: Path) -> RepoConfig:
    # url = the fixture path; local_path points nowhere so clone_at falls through to url.
    return RepoConfig(name="fixture", url=str(repo), local_path="no-such-checkout",
                      commit=_git(repo, "rev-parse", "HEAD").strip(),
                      image_hash_files=["requirements.txt", "missing.lock"],
                      image_install=["pip install --no-cache-dir -r requirements.txt"])


def _task(repo: Path, cfg: RepoConfig) -> Task:
    hidden = f"{sys.executable} -m pytest tests/security -q -x -p no:cacheprovider"
    return Task(task_id="P4-host-suffix-match", eval_id="security.agent.fixture.v1", repo="fixture",
                repo_url=str(repo), commit=cfg.commit, property="P4",
                description="suffix match", file="guard.py", find=FIND, replace=REPLACE,
                hidden_test=hidden, suite_test=hidden,
                container_test=["python", "-m", "pytest", "tests/security", "-q", "-x", "-p", "no:cacheprovider"],
                pythonpath=["."], agent="agents/egress.md", canary="c", repo_path=str(repo))


# ------------------------------------------------------------------ mode selection

def test_make_env_auto_is_local_without_docker(monkeypatch):
    monkeypatch.setattr(envmod, "docker_available", lambda: False)
    env = make_env("auto")
    assert isinstance(env, LocalEnv) and env.mode == "local" and env.workdir is None


def test_make_env_auto_is_container_with_docker(monkeypatch):
    monkeypatch.setattr(envmod, "docker_available", lambda: True)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("construction must not call docker"))
    env = make_env("auto", mem_mb=1024, pids=32, timeout_s=60)
    assert isinstance(env, ContainerEnv) and env.mode == "container" and env.workdir is None
    assert (env.mem_mb, env.pids, env.timeout_s) == (1024, 32, 60)


def test_make_env_container_raises_without_docker(monkeypatch):
    monkeypatch.setattr(envmod, "docker_available", lambda: False)
    with pytest.raises(RuntimeError, match="docker is unavailable"):
        make_env("container")
    assert isinstance(make_env("local"), LocalEnv)
    with pytest.raises(ValueError):
        make_env("podman")


def test_docker_available_never_starts_anything(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert docker_available() is False

    calls = []
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/docker")

    def failing_info(argv, **kw):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 1, b"", b"Cannot connect to the Docker daemon")
    monkeypatch.setattr(subprocess, "run", failing_info)
    assert docker_available() is False
    assert calls == [["docker", "info"]]

    def hanging_info(argv, **kw):
        raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
    monkeypatch.setattr(subprocess, "run", hanging_info)
    assert docker_available() is False

    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"", b""))
    assert docker_available() is True


# ------------------------------------------------------------------ pure argv builders

def test_container_argv_shape(tmp_path):
    work = tmp_path / "work"
    envf = tmp_path / "env.list"
    argv = container_argv("sa-env-abc", "sa-agent-eval/x:deadbeef0000", work, mem_mb=2048, pids=64,
                          cpu_s=600, env_file=envf, uid=501, gid=20)
    joined = " ".join(argv)
    assert argv[:3] == ["docker", "run", "-d"]
    for flag in ("--rm", "--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                 "--pids-limit 64", "--memory 2048m", "--user 501:20", "--tmpfs /tmp", "-w /work",
                 f"--env-file {envf}", "--name sa-env-abc"):
        assert flag in joined, flag
    assert any(a.startswith("fsize=") for a in argv) and "--ulimit" in argv
    assert any(a == "cpu=600:630" for a in argv)
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert mounts == [f"{work.resolve()}:/work:rw"]
    assert argv[-3:] == ["sa-agent-eval/x:deadbeef0000", "sleep", "infinity"]
    # `--network none` is the only network flag; nothing publishes a port.
    assert "-p" not in argv and "--publish" not in argv and "--privileged" not in argv


def test_exec_argv_shape():
    assert exec_argv("sa-env-abc", ["python", "-m", "pytest", "-q"]) == \
        ["docker", "exec", "-w", "/work", "sa-env-abc", "python", "-m", "pytest", "-q"]
    with_env = exec_argv("c", ["ls"], env={"HOME": "/tmp"})
    assert with_env[:6] == ["docker", "exec", "-w", "/work", "-e", "HOME=/tmp"]


def test_requirements_hash_and_tag(tmp_path):
    cfg = RepoConfig(name="Fixture Repo", url="x", local_path="x", commit="0" * 40,
                     image_hash_files=["requirements.txt", "uv.lock"], image_install=["pip install -r requirements.txt"])
    (tmp_path / "requirements.txt").write_text("pytest==8.0.0\n")
    h1 = requirements_hash(tmp_path, cfg)
    assert h1 == requirements_hash(tmp_path, cfg)                  # stable, missing uv.lock tolerated
    (tmp_path / "other.py").write_text("print(1)\n")
    assert requirements_hash(tmp_path, cfg) == h1                  # unrelated files do not matter
    (tmp_path / "requirements.txt").write_text("pytest==8.1.0\n")
    h2 = requirements_hash(tmp_path, cfg)
    assert h2 != h1
    (tmp_path / "uv.lock").write_text("lock\n")
    assert requirements_hash(tmp_path, cfg) != h2                  # a hash file appearing changes it
    tag = image_tag(cfg, h1)
    assert tag == f"sa-agent-eval/fixture-repo:{h1[:12]}"
    df = dockerfile(cfg)
    assert df.startswith("FROM python:3.12-slim\n") and "RUN pip install -r requirements.txt" in df
    assert "RUN pip install --no-cache-dir pytest" in df and "COPY src/ /src/" in df


def test_allowed_env_strips_secret_names():
    src = {"PATH": "/usr/bin", "LANG": "C", "ANTHROPIC_API_KEY": "x", "FOO_TOKEN": "y", "AWS_SECRET_ACCESS_KEY": "z",
           "SA_W1_CANARY": "1", "HOME": "/Users/someone"}
    env = allowed_env(src, set={"HOME": "/tmp/h", "PYTHONPATH": "/w", "MY_KEY": "never"})
    assert env == {"PATH": "/usr/bin", "LANG": "C", "HOME": "/tmp/h", "PYTHONPATH": "/w"}
    assert allowed_env(src, set={}, inherit=["ANTHROPIC_API_KEY", "FOO_TOKEN", "LANG"]) == {"LANG": "C"}


# ------------------------------------------------------------------ ContainerEnv.reset with docker faked

class FakeDocker:
    """Records every docker argv; git (and anything else) passes through to the real run."""

    def __init__(self, image_exists: bool):
        self.image_exists = image_exists
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):
        argv = list(argv)
        if argv[0] != "docker":
            return REAL_RUN(argv, **kw)
        self.calls.append(argv)
        sub = argv[1:3]
        if sub == ["image", "inspect"] and "--format" not in argv:
            return subprocess.CompletedProcess(argv, 0 if self.image_exists else 1, "", "" if self.image_exists else "No such image")
        if sub == ["image", "inspect"] and "{{index .RepoDigests 0}}" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "template: error calling index: index out of range")
        if sub == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "sha256:" + "ab" * 32 + "\n", "")
        if argv[1] == "build":
            ctx = Path(argv[-1])
            assert (ctx / "Dockerfile").is_file() and (ctx / "src" / "guard.py").is_file()
            assert not (ctx / "src" / ".git").exists()
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1] == "run":
            return subprocess.CompletedProcess(argv, 0, "c0ffee\n", "")
        if argv[1] in ("rm", "kill"):
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(f"unexpected docker call {argv}")

    def of(self, *prefix):
        return [c for c in self.calls if c[1:1 + len(prefix)] == list(prefix)]


@pytest.mark.parametrize("cached", [True, False])
def test_container_reset_records_docker_invocations(fixture_repo, tmp_path, monkeypatch, cached):
    cfg = _cfg(fixture_repo)
    task = _task(fixture_repo, cfg)
    fake = FakeDocker(image_exists=cached)
    monkeypatch.setattr(subprocess, "run", fake)
    env = ContainerEnv(repos={"fixture": cfg}, image_cache=tmp_path / "cache", mem_mb=512, pids=32, timeout_s=120)
    info = env.reset(task)
    try:
        assert info.mode == "container" and info.workdir == env.workdir and info.container == env.container
        assert info.image == image_tag(cfg, requirements_hash(env.workdir, cfg))
        assert info.image_digest == "sha256:" + "ab" * 32
        assert info.limits["mem_mb"] == 512 and info.limits["pids"] == 32 and info.limits["network"] == "none"
        # the clone is mutated and the mutation is committed
        assert REPLACE in (env.workdir / "guard.py").read_text()
        assert "mutation P4-host-suffix-match" in _git(env.workdir, "log", "--oneline")
        assert env.diff() == ""
        # build only when the image is missing
        assert len(fake.of("build")) == (0 if cached else 1)
        runs = fake.of("run")
        assert len(runs) == 1
        name = runs[0][runs[0].index("--name") + 1]
        env_file = Path(runs[0][runs[0].index("--env-file") + 1])
        assert runs[0] == container_argv(name, info.image, env.workdir, mem_mb=512, pids=32, cpu_s=env.cpu_s,
                                         env_file=env_file)
        assert env_file.is_file() and not str(env_file).startswith(str(env.workdir))
        lines = env_file.read_text().splitlines()
        assert "HOME=/tmp" in lines and "PYTHONPATH=/work" in lines and "PYTHONDONTWRITEBYTECODE=1" in lines
        assert not any(l.startswith("ANTHROPIC") for l in lines)
        tmp = env._tmp
    finally:
        env.close()
    assert fake.of("rm") and fake.of("rm")[-1] == ["docker", "rm", "-f", name]
    assert not tmp.exists() and env.workdir is None and env.container is None
    env.close()                                                   # idempotent


def test_build_image_skips_when_cached(tmp_path, monkeypatch):
    cfg = RepoConfig(name="f", url="x", local_path="x", commit="0" * 40, image_install=["true"])
    (tmp_path / "src").mkdir()
    fake = FakeDocker(image_exists=True)
    monkeypatch.setattr(subprocess, "run", fake)
    assert build_image(cfg, tmp_path / "src", "sa-agent-eval/f:abc") == "sha256:" + "ab" * 32
    assert fake.of("build") == []


# ------------------------------------------------------------------ LocalEnv end to end

def test_local_env_end_to_end(fixture_repo, monkeypatch):
    cfg = _cfg(fixture_repo)
    task = _task(fixture_repo, cfg)
    monkeypatch.setenv("SA_W1_CANARY", "leaked")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "not-a-real-key")
    env = LocalEnv(repos={"fixture": cfg}, timeout_s=60)
    info = env.reset(task)
    work = env.workdir
    assert info.mode == "local" and env.mode == "local" and info.workdir == work
    assert info.image is None and info.container is None and info.limits["python"] == sys.executable
    assert work != fixture_repo and work.is_dir() and (work / ".git").is_dir()

    # the mutation is in the clone, committed, and not part of the diff
    assert REPLACE in (work / "guard.py").read_text()
    assert FIND in (fixture_repo / "guard.py").read_text()          # the source repo is untouched
    log = _git(work, "log", "--format=%an %s")
    assert log.splitlines()[0] == "harness mutation P4-host-suffix-match"
    assert env.diff() == ""

    r = env.exec(["python", "-c", "print(1)"])
    assert (r.returncode, r.stdout.strip(), r.timed_out) == (0, "1", False)

    r = env.exec(task.container_test)                              # the pinned test catches the mutation
    assert r.returncode != 0 and "test_only_the_allow_listed_host_passes" in r.stdout

    # the child sees only the allow-list: no canary, no key, HOME under the env's temp dir
    r = env.exec(["python", "-c",
                  "import os; print(os.environ.get('SA_W1_CANARY')); print(os.environ.get('ANTHROPIC_API_KEY')); "
                  "print(os.environ['HOME']); print(os.getcwd())"])
    assert r.returncode == 0, r.stderr
    canary, key, home, cwd = r.stdout.splitlines()
    assert canary == "None" and key == "None"
    assert Path(home) != Path.home() and Path(home).is_relative_to(env._tmp)
    assert Path(cwd).resolve() == work.resolve()

    # editing the clone from the host (as the graders/baselines do) shows up in diff()
    (work / "guard.py").write_text(MODULE)
    (work / "notes.txt").write_text("new\n")
    d = env.diff()
    assert "diff --git a/guard.py b/guard.py" in d and "diff --git a/notes.txt b/notes.txt" in d
    assert "new file mode" in d and f"+    return {FIND}" in d
    status = _git(work, "status", "--porcelain")
    assert "?? notes.txt" in status and " M guard.py" in status      # no intent-to-add left behind
    assert env.exec(task.container_test).returncode == 0           # the restored file passes

    t0 = time.monotonic()
    r = env.exec(["python", "-c", "import time; time.sleep(30)"], timeout_s=1)
    assert r.returncode == 124 and r.timed_out and "timeout after 1s" in r.stderr
    assert time.monotonic() - t0 < 10

    tmp = env._tmp
    env.close()
    assert not tmp.exists() and env.workdir is None
    env.close()
    with pytest.raises(RuntimeError):
        env.exec(["python", "-c", "1"])


def test_local_env_unknown_repo(fixture_repo):
    cfg = _cfg(fixture_repo)
    task = _task(fixture_repo, cfg)
    env = LocalEnv(repos={"other": cfg})
    with pytest.raises(ValueError, match="unknown repo"):
        env.reset(task)
    assert env.workdir is None and env._tmp is None


def test_interpreter_resolution(fixture_repo, tmp_path):
    cfg = _cfg(fixture_repo)
    base = _task(fixture_repo, cfg)
    # a relative venv path resolves against repo_path, not the clone
    venv = fixture_repo / ".venv" / "bin"
    venv.mkdir(parents=True)
    fake_py = venv / "python"
    fake_py.write_text("#!/bin/sh\n")
    import dataclasses
    t = dataclasses.replace(base, hidden_test=".venv/bin/python -m pytest tests/security -q")
    assert LocalEnv.interpreter_for(t) == str(fake_py)
    # a venv that does not exist, a bare name, or no checkout at all -> sys.executable
    assert LocalEnv.interpreter_for(dataclasses.replace(base, hidden_test=".venv-sec/bin/python -m pytest")) == sys.executable
    assert LocalEnv.interpreter_for(dataclasses.replace(base, hidden_test="python -m pytest")) == sys.executable
    assert LocalEnv.interpreter_for(dataclasses.replace(base, repo_path=None)) == sys.executable
