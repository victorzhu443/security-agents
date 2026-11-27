"""The environment of the agent-eval harness: a fresh, mutated clone the model's commands
run in, boxed (EVALS-PLAN.md Phase 7 work item 1; the `Env` protocol in types.py).

Two implementations of the same contract:

    ContainerEnv   docker present and answering: the clone is the ONLY writable mount of a
                   long-lived container started with the research-replication-agent
                   sandbox's flags (`--rm --network none --read-only --cap-drop ALL
                   --security-opt no-new-privileges --user uid:gid --memory --pids-limit
                   --ulimit fsize/cpu --tmpfs /tmp`) and `sleep infinity` as its command,
                   so `exec` can `docker exec` many commands into one box. The image is
                   python:3.12-slim + the repo's `image.install` recipe + pytest, built once
                   WITH network and cached by the sha256 of the repo's requirement files.
    LocalEnv       docker absent (this Mac: colima installed but stopped, and nothing here
                   ever starts it): the same clone in a temp dir, commands run with the
                   sandbox's local-mode rlimits (`RLIMIT_AS/CPU/NPROC/FSIZE`, each attempted
                   on its own), an allow-listed environment, a new session and a
                   process-group SIGKILL on timeout. `mode == "local"` is recorded in the
                   provenance so a run without network isolation is never silent.

Both: `reset(task)` = `repos.clone_at` -> `evals.mutate.apply_mutation` -> commit the
mutation inside the clone (so `diff()` is only what the agent changed), `exec(argv)` runs
one argv (never a shell string) with cwd = the clone, `diff()` is the clone's working tree
against that commit with untracked files as additions, `close()` tears down (idempotent).

What is deliberately NOT here: the sandbox's psutil RSS watchdog (no psutil dependency;
in local mode memory is bounded only by `RLIMIT_AS`, which macOS treats as advisory —
container mode bounds it with `--memory`), anything that reads `ANTHROPIC_*`, calls a
model, or imports the `anthropic` package.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from evals.mutate import Mutation, apply_mutation, resolve_command

from .repos import RepoConfig, clone_at, load_repos
from .types import CONTAINER_PYTHON, CONTAINER_WORKDIR, Env, ExecResult, ResetInfo, Task

BASE_IMAGE = "python:3.12-slim"
IMAGE_PREFIX = "sa-agent-eval"
DEFAULT_MEM_MB = 2048
DEFAULT_PIDS = 64
DEFAULT_TIMEOUT_S = 600
DEFAULT_NPROC = 2048                      # the sandbox's; RRA's containment tests spawn processes
DEFAULT_FSIZE_BYTES = 16 * 1024 ** 3      # the sandbox's 16 GiB
OUTPUT_TAIL = 20000                       # chars of stdout/stderr kept, from the end
DOCKER_INFO_TIMEOUT_S = 10
DOCKER_BUILD_TIMEOUT_S = 1800
MUTATION_COMMIT_IDENTITY = ("-c", "user.name=harness", "-c", "user.email=harness@local",
                            "-c", "commit.gpgsign=false")

#: Names never copied into a child environment, even when a caller allow-lists them.
SECRET_NAME = re.compile(r"^ANTHROPIC_|_KEY$|_TOKEN$|_SECRET", re.IGNORECASE)
#: What a local-mode child may inherit from this process, beyond what is set explicitly.
LOCAL_INHERIT = ("PATH", "LANG", "LC_ALL")


# ------------------------------------------------------------------ docker presence

def docker_available() -> bool:
    """True when the `docker` CLI is on PATH AND the daemon answers `docker info` within
    10 s. Never starts, installs or configures anything: a stopped colima makes this False."""
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True,
                              timeout=DOCKER_INFO_TIMEOUT_S).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def make_env(mode: str = "auto", *, image_cache: Optional[Path] = None, mem_mb: int = DEFAULT_MEM_MB,
             pids: int = DEFAULT_PIDS, timeout_s: int = DEFAULT_TIMEOUT_S,
             repos: Optional[Dict[str, RepoConfig]] = None) -> Env:
    """`auto` -> ContainerEnv when `docker_available()` else LocalEnv; `container` raises
    RuntimeError when docker is unavailable (it is never started here); `local` always local."""
    if mode not in ("auto", "container", "local"):
        raise ValueError(f"unknown env mode {mode!r} (expected auto|container|local)")
    if mode == "local":
        return LocalEnv(repos=repos, mem_mb=mem_mb, timeout_s=timeout_s)
    available = docker_available()
    if mode == "container" and not available:
        raise RuntimeError("env mode 'container' requested but docker is unavailable "
                           "(no CLI, or the daemon is not running); not starting it. Use --mode local.")
    if available:
        return ContainerEnv(repos=repos, image_cache=image_cache, mem_mb=mem_mb, pids=pids, timeout_s=timeout_s)
    return LocalEnv(repos=repos, mem_mb=mem_mb, timeout_s=timeout_s)


# ------------------------------------------------------------------ pure helpers (tested by shape)

def container_argv(name: str, image: str, workdir: Path, *, mem_mb: int = DEFAULT_MEM_MB,
                   pids: int = DEFAULT_PIDS, cpu_s: int = DEFAULT_TIMEOUT_S,
                   fsize_bytes: int = DEFAULT_FSIZE_BYTES, env_file: Optional[Path] = None,
                   uid: Optional[int] = None, gid: Optional[int] = None) -> List[str]:
    """The `docker run -d ... sleep infinity` argv: the sandbox's `_container_argv` flags, the
    clone as the only mount (rw at /work), `--init` so processes orphaned by one `exec` are
    reaped instead of counting against `--pids-limit`, and a sleeping PID 1 for `exec` to
    join. The process runs as the host uid:gid so the mounted clone stays writable on Linux."""
    uid = os.getuid() if uid is None else uid
    gid = os.getgid() if gid is None else gid
    argv = ["docker", "run", "-d", "--rm", "--init", "--name", name,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--user", f"{uid}:{gid}",
            "--memory", f"{int(mem_mb)}m", "--pids-limit", str(int(pids)),
            "--ulimit", f"fsize={int(fsize_bytes)}:{int(fsize_bytes)}",
            "--ulimit", f"cpu={int(cpu_s)}:{int(cpu_s) + 30}",
            "--tmpfs", "/tmp", "-v", f"{Path(workdir).resolve()}:{CONTAINER_WORKDIR}:rw",
            "-w", CONTAINER_WORKDIR]
    if env_file is not None:
        argv += ["--env-file", str(env_file)]
    return argv + [image, "sleep", "infinity"]


def exec_argv(container: str, argv: Sequence[str], *, workdir: str = CONTAINER_WORKDIR,
              env: Optional[Dict[str, str]] = None) -> List[str]:
    """The `docker exec` argv for one command inside `container`, cwd `workdir`."""
    out = ["docker", "exec", "-w", workdir]
    for k, v in (env or {}).items():
        out += ["-e", f"{k}={v}"]
    return out + [container, *argv]


def requirements_hash(workdir: Path, cfg: RepoConfig) -> str:
    """sha256 over `cfg.image_hash_files` as they are in `workdir` (the clone at the pinned
    commit), plus the base image and install recipe, so a changed recipe also misses the
    cache. A missing file hashes as `<missing>` rather than raising (uv.lock is optional)."""
    h = hashlib.sha256()
    h.update((cfg.base_image or BASE_IMAGE).encode())
    for step in cfg.image_install:
        h.update(b"\0install:" + step.encode())
    for rel in cfg.image_hash_files:
        p = Path(workdir) / rel
        h.update(b"\0file:" + rel.encode() + b"\0")
        h.update(p.read_bytes() if p.is_file() else b"<missing>")
    return h.hexdigest()


def image_tag(cfg: RepoConfig, requirements_hash: str) -> str:
    name = re.sub(r"[^a-z0-9._-]+", "-", cfg.name.lower()).strip("-") or "repo"
    return f"{IMAGE_PREFIX}/{name}:{requirements_hash[:12]}"


def dockerfile(cfg: RepoConfig) -> str:
    """`cfg.base_image` (default python:3.12-slim) + git (the recipes pip-install from git+https) + the repo's install
    steps run inside a COPY of the clone at /src + pytest. Tests run from the /work mount,
    never from /src."""
    lines = [f"FROM {cfg.base_image or BASE_IMAGE}",
             "ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore PYTHONDONTWRITEBYTECODE=1",
             "RUN apt-get update && apt-get install -y --no-install-recommends git "
             "&& rm -rf /var/lib/apt/lists/*",
             "COPY src/ /src/", "WORKDIR /src"]
    lines += [f"RUN {step}" for step in cfg.image_install]
    lines += ["RUN pip install --no-cache-dir pytest", f"WORKDIR {CONTAINER_WORKDIR}"]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ docker plumbing

def _docker(args: Sequence[str], *, timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=check)


def image_exists(tag: str) -> bool:
    try:
        return _docker(["image", "inspect", tag]).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def image_digest(tag: str) -> str:
    """`RepoDigests[0]` when the image came from a registry, else the local `.Id`."""
    r = _docker(["image", "inspect", "--format", "{{index .RepoDigests 0}}", tag])
    digest = (r.stdout or "").strip()
    if r.returncode == 0 and digest:
        return digest
    r = _docker(["image", "inspect", "--format", "{{.Id}}", tag])
    return (r.stdout or "").strip()


def build_image(cfg: RepoConfig, workdir: Path, tag: str, *, build_dir: Optional[Path] = None) -> str:
    """Build `tag` from `dockerfile(cfg)` in a temp context holding a copy of the clone
    (minus .git); skipped when `docker image inspect <tag>` already succeeds. The one step
    with network. Returns the image digest."""
    if not image_exists(tag):
        if build_dir is not None:
            Path(build_dir).mkdir(parents=True, exist_ok=True)
        ctx = Path(tempfile.mkdtemp(prefix="sa-image-", dir=str(build_dir) if build_dir else None))
        try:
            shutil.copytree(workdir, ctx / "src", symlinks=True, ignore=shutil.ignore_patterns(".git"))
            (ctx / "Dockerfile").write_text(dockerfile(cfg))
            r = _docker(["build", "-t", tag, str(ctx)], timeout=DOCKER_BUILD_TIMEOUT_S)
            if r.returncode != 0:
                raise RuntimeError(f"docker build of {tag} failed (rc {r.returncode}):\n{(r.stderr or '')[-4000:]}")
        finally:
            shutil.rmtree(ctx, ignore_errors=True)
    return image_digest(tag)


# ------------------------------------------------------------------ shared clone/mutation/diff

def _git(work: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(work), *args], capture_output=True, text=True, check=check)


def _prepare_clone(repos: Dict[str, RepoConfig], task: Task, dest: Path) -> Path:
    """Clone at the task's commit, apply the mutation, commit it as `harness` so the agent's
    later edits are the whole of `git diff`."""
    if task.repo not in repos:
        raise ValueError(f"task {task.task_id!r} names unknown repo {task.repo!r}; known: {', '.join(repos)}")
    cfg = repos[task.repo]
    if task.commit and task.commit != cfg.commit:
        cfg = dataclasses.replace(cfg, commit=task.commit)      # the task record is authoritative
    work = clone_at(cfg, dest)
    apply_mutation(work, Mutation(id=task.task_id, property=task.property, file=task.file,
                                  find=task.find, replace=task.replace, description=task.description,
                                  test=task.hidden_test))
    _git(work, *MUTATION_COMMIT_IDENTITY, "commit", "-qam", f"mutation {task.task_id}")
    return work


def _tree_diff(work: Path) -> str:
    """Working tree vs HEAD with untracked (non-ignored) files as additions: `add -N` makes
    them intent-to-add so `git diff` renders `diff --git a/x b/x` + `new file mode`, then
    `reset -q` drops that index state so a later `git checkout <commit> -- file` is unaffected."""
    _git(work, "add", "-N", ".")
    try:
        return _git(work, "diff", "--no-color", "--no-ext-diff").stdout
    finally:
        _git(work, "reset", "-q", check=False)


def _pythonpath(work: Path, task: Optional[Task], *, prefix: str) -> str:
    entries = [prefix]
    for rel in (task.pythonpath if task else []):
        p = os.path.normpath(os.path.join(prefix, rel))
        if p not in entries:
            entries.append(p)
    return ":".join(entries)


def _tail(s: Optional[str]) -> str:
    return (s or "")[-OUTPUT_TAIL:]


def _killpg(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _run_bounded(popen_argv: Sequence[str], *, cwd: Optional[Path], env: Optional[Dict[str, str]],
                 preexec_fn, timeout_s: int, on_timeout=None) -> ExecResult:
    """Popen in a new session, wall-clock timeout, process-group SIGKILL (and `on_timeout`
    first, e.g. `docker kill`) -> rc 124; output kept from the end."""
    t0 = time.monotonic()
    proc = subprocess.Popen(list(popen_argv), cwd=str(cwd) if cwd else None, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            preexec_fn=preexec_fn, start_new_session=True)
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        if on_timeout is not None:
            on_timeout()
        _killpg(proc)
        try:
            out, err = proc.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = "", ""
    rc = proc.returncode
    if timed_out:
        rc, err = 124, _tail(err) + f"\ntimeout after {timeout_s}s"
    return ExecResult(returncode=rc, stdout=_tail(out), stderr=_tail(err),
                      seconds=time.monotonic() - t0, timed_out=timed_out)


# ------------------------------------------------------------------ container mode

class ContainerEnv:
    """`Env` in container mode. Construction touches nothing; `reset` clones, builds or
    reuses the image, and starts the box. If a command times out the container is killed
    (`--rm` removes it) and the next `exec` starts a fresh one on the same mount, so the
    clone's state survives but the dead container's processes do not."""
    mode = "container"

    def __init__(self, *, repos: Optional[Dict[str, RepoConfig]] = None, image_cache: Optional[Path] = None,
                 mem_mb: int = DEFAULT_MEM_MB, pids: int = DEFAULT_PIDS, timeout_s: int = DEFAULT_TIMEOUT_S,
                 fsize_bytes: int = DEFAULT_FSIZE_BYTES):
        self._repos = repos
        self.image_cache = Path(image_cache) if image_cache else None
        self.mem_mb, self.pids, self.timeout_s, self.fsize_bytes = int(mem_mb), int(pids), int(timeout_s), int(fsize_bytes)
        self.cpu_s = self.timeout_s * max(1, os.cpu_count() or 1)     # the sandbox's: per process, all cores
        self.workdir: Optional[Path] = None
        self.task: Optional[Task] = None
        self.image: Optional[str] = None
        self.image_digest: Optional[str] = None
        self.container: Optional[str] = None
        self._tmp: Optional[Path] = None
        self._env_file: Optional[Path] = None

    @property
    def repos(self) -> Dict[str, RepoConfig]:
        if self._repos is None:
            self._repos = load_repos()
        return self._repos

    def _limits(self) -> Dict[str, Any]:
        return {"mem_mb": self.mem_mb, "pids": self.pids, "cpu_s": self.cpu_s, "cpu_hard_s": self.cpu_s + 30,
                "fsize_bytes": self.fsize_bytes, "network": "none", "read_only_root": True,
                "writable": CONTAINER_WORKDIR, "tmpfs": "/tmp", "user": f"{os.getuid()}:{os.getgid()}"}

    def _container_env(self) -> Dict[str, str]:
        assert self.workdir is not None
        return {"HOME": "/tmp", "TMPDIR": "/tmp", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": _pythonpath(self.workdir, self.task, prefix=CONTAINER_WORKDIR),
                "PIP_NO_INDEX": "1"}

    def _start_container(self) -> str:
        assert self.workdir is not None and self.image is not None and self._tmp is not None
        if self._env_file is None:
            self._env_file = self._tmp / "env.list"            # outside the mount
            self._env_file.write_text("".join(f"{k}={v}\n" for k, v in self._container_env().items()))
        name = f"sa-env-{uuid.uuid4().hex[:12]}"
        argv = container_argv(name, self.image, self.workdir, mem_mb=self.mem_mb, pids=self.pids,
                              cpu_s=self.cpu_s, fsize_bytes=self.fsize_bytes, env_file=self._env_file)
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"docker run failed (rc {r.returncode}): {(r.stderr or '')[-2000:]}")
        self.container = name
        return name

    def _stop_container(self) -> None:
        if self.container is None:
            return
        name, self.container = self.container, None
        try:
            _docker(["rm", "-f", name], timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass

    def reset(self, task: Task) -> ResetInfo:
        self.close()
        self._tmp = Path(tempfile.mkdtemp(prefix=f"sa-env-{task.repo}-"))
        try:
            cfg = self.repos.get(task.repo)
            if cfg is None:
                raise ValueError(f"task {task.task_id!r} names unknown repo {task.repo!r}; known: {', '.join(self.repos)}")
            work = _prepare_clone(self.repos, task, self._tmp / "work")
            tag = image_tag(cfg, requirements_hash(work, cfg))      # hash files are not mutation targets
            digest = build_image(cfg, work, tag, build_dir=self.image_cache)
            self.workdir, self.task, self.image, self.image_digest = work, task, tag, digest
            name = self._start_container()
        except BaseException:
            self.close()
            raise
        return ResetInfo(mode=self.mode, workdir=work, image=tag, image_digest=digest,
                         container=name, limits=self._limits())

    def exec(self, argv: Sequence[str], *, timeout_s: int = DEFAULT_TIMEOUT_S) -> ExecResult:
        if self.workdir is None:
            raise RuntimeError("ContainerEnv.exec before reset")
        argv = list(argv)
        if not argv:
            raise ValueError("empty argv")
        if argv[0] in ("python3", sys.executable):
            argv[0] = CONTAINER_PYTHON
        name = self.container or self._start_container()

        def kill() -> None:
            try:
                _docker(["kill", name], timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass
            self.container = None            # `--rm` removed it; the next exec starts a new box

        return _run_bounded(exec_argv(name, argv), cwd=None, env=None, preexec_fn=None,
                            timeout_s=timeout_s, on_timeout=kill)

    def diff(self) -> str:
        if self.workdir is None:
            raise RuntimeError("ContainerEnv.diff before reset")
        return _tree_diff(self.workdir)

    def close(self) -> None:
        self._stop_container()
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)
        self._tmp = self._env_file = None
        self.workdir = self.task = self.image = self.image_digest = None


# ------------------------------------------------------------------ local mode

def _set_rlimits(mem_bytes: int, cpu_s: int, nproc: int, fsize_bytes: int) -> None:
    """preexec_fn (the sandbox's `_limits`): each limit attempted on its own, clamped to the
    inherited hard limit; an unsupported one is skipped, never the whole set. RLIMIT_AS is
    advisory on macOS (the kernel does not enforce it); there is no RSS watchdog here."""
    for name, soft, hard in (("RLIMIT_AS", mem_bytes, mem_bytes),
                             ("RLIMIT_CPU", cpu_s, cpu_s + 30),
                             ("RLIMIT_NPROC", nproc, nproc),
                             ("RLIMIT_FSIZE", fsize_bytes, fsize_bytes)):
        rid = getattr(resource, name, None)
        if rid is None:
            continue
        try:
            _, cur_hard = resource.getrlimit(rid)
            if cur_hard != resource.RLIM_INFINITY:
                soft, hard = min(soft, cur_hard), min(hard, cur_hard)
            resource.setrlimit(rid, (soft, hard))
        except (ValueError, OSError):
            continue


def allowed_env(source: Dict[str, str], *, set: Dict[str, str], inherit: Iterable[str] = LOCAL_INHERIT) -> Dict[str, str]:
    """Build a child environment from nothing: `set` values, then the `inherit` names copied
    from `source` when present and not secret-shaped (`ANTHROPIC_*`, `*_KEY`, `*_TOKEN`,
    `*_SECRET*` never cross, whatever the allow-list says). Never `os.environ` wholesale."""
    env: Dict[str, str] = {}
    for k in inherit:
        if k in source and not SECRET_NAME.search(k):
            env[k] = source[k]
    for k, v in set.items():
        if not SECRET_NAME.search(k):
            env[k] = v
    return env


class LocalEnv:
    """`Env` in local mode (docker unavailable). Same clone and mutation commit; commands run
    on the host with cwd = the clone, an allow-listed environment, the sandbox's rlimits,
    a new session and a process-group SIGKILL on timeout. `python`/`python3` in argv[0] is
    replaced by the interpreter the catalogue's test command names, resolved against the
    local checkout (`task.repo_path`, whose venv is gitignored and so absent from the
    clone), else by `sys.executable`. No network restriction: provenance says `local`."""
    mode = "local"

    def __init__(self, *, repos: Optional[Dict[str, RepoConfig]] = None, mem_mb: int = DEFAULT_MEM_MB,
                 timeout_s: int = DEFAULT_TIMEOUT_S, nproc: int = DEFAULT_NPROC,
                 fsize_bytes: int = DEFAULT_FSIZE_BYTES):
        self._repos = repos
        self.mem_mb, self.timeout_s, self.nproc, self.fsize_bytes = int(mem_mb), int(timeout_s), int(nproc), int(fsize_bytes)
        self.cpu_s = self.timeout_s * max(1, os.cpu_count() or 1)
        self.workdir: Optional[Path] = None
        self.task: Optional[Task] = None
        self.python: Optional[str] = None
        self._tmp: Optional[Path] = None

    @property
    def repos(self) -> Dict[str, RepoConfig]:
        if self._repos is None:
            self._repos = load_repos()
        return self._repos

    @staticmethod
    def interpreter_for(task: Task) -> str:
        """argv[0] of `task.hidden_test` resolved against `task.repo_path` (evals.mutate's
        rule: a relative `.venv/bin/python` lives in the checkout, not the clone). A bare
        name, a missing venv or no local checkout -> `sys.executable`."""
        if task.repo_path and task.hidden_test:
            try:
                head = resolve_command(task.hidden_test, Path(task.repo_path))[0]
            except (FileNotFoundError, ValueError):
                return sys.executable
            if os.path.isabs(head) and os.path.exists(head):
                return head
        return sys.executable

    def _child_env(self) -> Dict[str, str]:
        assert self.workdir is not None and self._tmp is not None
        home, tmp = self._tmp / "home", self._tmp / "tmp"
        home.mkdir(exist_ok=True)
        tmp.mkdir(exist_ok=True)
        return allowed_env(os.environ, set={
            "HOME": str(home), "TMPDIR": str(tmp), "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": _pythonpath(self.workdir, self.task, prefix=str(self.workdir)),
        })

    def _limits(self) -> Dict[str, Any]:
        return {"mem_mb": self.mem_mb, "cpu_s": self.cpu_s, "cpu_hard_s": self.cpu_s + 30, "nproc": self.nproc,
                "fsize_bytes": self.fsize_bytes, "network": "unrestricted", "rlimit_as_enforced": sys.platform != "darwin",
                "python": self.python}

    def reset(self, task: Task) -> ResetInfo:
        self.close()
        self._tmp = Path(tempfile.mkdtemp(prefix=f"sa-env-{task.repo}-"))
        try:
            work = _prepare_clone(self.repos, task, self._tmp / "work")
        except BaseException:
            self.close()
            raise
        self.workdir, self.task, self.python = work, task, self.interpreter_for(task)
        return ResetInfo(mode=self.mode, workdir=work, image=None, image_digest=None, container=None,
                         limits=self._limits())

    def exec(self, argv: Sequence[str], *, timeout_s: int = DEFAULT_TIMEOUT_S) -> ExecResult:
        if self.workdir is None:
            raise RuntimeError("LocalEnv.exec before reset")
        argv = list(argv)
        if not argv:
            raise ValueError("empty argv")
        if argv[0] in ("python", "python3"):
            argv[0] = self.python or sys.executable
        mem_bytes, cpu_s, nproc, fsize = self.mem_mb * 1024 ** 2, self.cpu_s, self.nproc, self.fsize_bytes
        return _run_bounded(argv, cwd=self.workdir, env=self._child_env(),
                            preexec_fn=lambda: _set_rlimits(mem_bytes, cpu_s, nproc, fsize),
                            timeout_s=timeout_s)

    def diff(self) -> str:
        if self.workdir is None:
            raise RuntimeError("LocalEnv.diff before reset")
        return _tree_diff(self.workdir)

    def close(self) -> None:
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)
        self._tmp = None
        self.workdir = self.task = self.python = None
