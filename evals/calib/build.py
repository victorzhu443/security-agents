"""Candidate advisory -> Harbor task directory (evals/calib/CONTRACTS.md, W-B; amended 2026-11-27).

One candidate (a W-A `Candidate.to_record()` dict, co-selected at step 2) becomes one task dir:

    evals/calib/egress/tasks/<task_id>/
    ├── instruction.md            the one generic review text (class-blind by construction)
    ├── task.toml                 Harbor schema 1.4; [metadata] = the task record + build facts
    ├── task.json                 the Task record + fix_hunks / dependency_cutoff (also under tests/)
    ├── environment/Dockerfile    python:<minor>-slim; clone at vuln_commit at BUILD time; date-pinned
    │                             `uv pip install --system --exclude-newer=<fix-commit date>`; RewardKit in
    │                             its own venv (/opt/rewardkit); then a FRESH single-commit history
    ├── solution/solve.sh         `cd /app && git apply --index /solution/reference.patch`
    ├── solution/reference.patch  `git diff <vuln> <fix> -- <non-test fix files>`
    └── tests/                    W-C's verifier_assets/ tree + verify.py, copied in at build time, plus
        ├── task.json             (a stub test.sh exiting 2 when the assets are absent on this branch)
        └── hidden.patch          `git diff <vuln> <fix> -- <test files>` — positives only

Why the agent's tree holds no fix objects: a clone that still carries the fix commit lets
`git log` / `git show` leak the fix. The Dockerfile therefore clones with network at build
time, checks out `vuln_commit`, installs, then `rm -rf .git && git init -q && git add -A &&
git -c user.name=harness -c user.email=harness@local commit -qm task`. The reference fix cannot
be a checkout from `fix_commit` any more; it is `solution/reference.patch`, applied by Harbor's
oracle agent. Nothing under the task dir names the fix commit except `task.toml`/`task.json`
metadata, which the agent never sees (Harbor uploads tests/ after the agent runs; the agent
sees only /app and instruction.md).

Validity-gate rc rules (implemented by W-C's criteria, run by W-D's `calib-validate`; read from
reward-details.json): **nop run** (`-a nop`): `hidden_test_passes` 0 with `rc=1` — the hidden
test FAILED, not a collection/usage error (2/3/4/5) — and `suite_passes` 1 (`suite_rc == 0`);
**reference run** (`-a oracle`): both 1 (`fix_rc == 0`, `suite_rc == 0`); **negatives**: suite only
(`suite_rc == 0`, no hidden test — the builder writes no `tests/hidden.patch` for them, and the
`fix/` dimension checks for its presence). A task failing a rule is excluded `noop_passes`,
`reference_fails` or `suite_fails_at_vuln` by the gate, never silently kept.

Install-recipe discovery (prior art read 2026-11-27, SWE-bench/SWE-smith: `swesmith/profiles/python.py`
and `swesmith/build_repo/try_install_py.py`; detection ORDER borrowed, no code): their per-repo
profiles default to an editable install (`python -m pip install -e .`, Python 3.10) and override,
in frequency order, with extras (`-e .[dev]`, `-e .[test,doc]`), a requirements file
(`-r requirements.txt`, `-r test-requirements.txt`), system packages, and the legacy `setup.py
install`; a recipe is accepted only when `pytest -q --maxfail=1` runs in the resulting env.
Ours mirrors that order automatically — lockfile export, requirements files, editable install
with the test-ish extras, pytest — with every step date-pinned, and leaves the acceptance check
to the container validity gate (`build_fails_at_vuln` / `suite_fails_at_vuln`).

Everything here runs offline against a local clone; the only network is `git clone` of the
candidate's `repo_url` (tests use fake repos in tmp). Never imports `harbor`.
"""
from __future__ import annotations

import configparser
import dataclasses
import json
import re
import shlex
import shutil
import stat
import subprocess
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

from evals import calib
from evals.agent.repos import RepoConfig, clone_at, load_repos
from evals.agent.types import KIND_ADVISORY, SCOPE_REACHABLE_FROM_FIX, SOURCE_ADVISORY, Task

from .scope import scope_files

TASKS_DIR = calib.TASKS_DIR
TASKS_JSONL = calib.TASKS_JSONL
CALIB_REPOS_FILE = calib.CALIB_REPOS_FILE
EXCLUSIONS_FILE = calib.EXCLUSIONS_FILE

#: Amended constants (CONTRACTS.md "Amendments", A1/A6) with fallbacks equal to the governor's
#: values, so this module imports on a checkout that predates the amendment commit.
REWARDKIT_VERSION: str = getattr(calib, "REWARDKIT_VERSION", "0.2.4")
REWARDKIT_VENV: str = getattr(calib, "REWARDKIT_VENV", "/opt/rewardkit")
SAST_VENV = "/opt/sast"
CODEQL_DIR = "/opt/codeql"
#: W-C's verifier tree template and the pure-grader module copied next to it (A1).
VERIFIER_ASSETS_DIR = calib.CALIB_DIR / "verifier_assets"
VERIFY_PY = calib.CALIB_DIR / "verify.py"
#: First line of the stub tests/test.sh written when the verifier assets are absent.
STUB_MARKER = "# STUB verifier: evals/calib/verifier_assets/ was absent at build time (verifier_vendored: false)."

REVIEW_FIELDS = ("review_underspecified", "review_test_unfair")
_TASK_FIELDS = {f.name for f in dataclasses.fields(Task)}

#: Oldest slim tag uv's `--system` install supports; newest minor we will name.
PY_MIN, PY_MAX = (3, 8), (3, 16)
#: CPython minor -> first stable release date (python.org release history). Used as the era cap:
#: a commit never gets an interpreter younger than itself. 3.15 is the scheduled date (PEP 790).
PY_RELEASES = {(3, 8): "2019-10-14", (3, 9): "2020-10-05", (3, 10): "2021-10-04", (3, 11): "2022-10-24",
               (3, 12): "2023-10-02", (3, 13): "2024-10-07", (3, 14): "2025-10-07", (3, 15): "2026-10-01"}

__all__ = ["resolve_commits", "changed_files", "detect_library", "hidden_patch", "reference_patch",
           "fix_test_argv", "suite_test_argv", "python_requires", "image_recipe", "dockerfile",
           "task_toml", "instruction_text", "build_task", "build_all", "write_tasks_jsonl",
           "load_calib_repos", "load_base_digests", "is_test_path", "parse_hunks", "commit_date",
           "verifier_vendored", "needs_archive_apt", "task_record", "write_task_dir"]


# --------------------------------------------------------------------- git helpers

def _git(repo: Path, *args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True,
                          check=check, timeout=timeout)


def _show(repo: Path, commit: str, path: str) -> Optional[str]:
    r = _git(repo, "show", f"{commit}:{path}", check=False)
    return r.stdout if r.returncode == 0 else None


def _tree(repo: Path, commit: str) -> List[str]:
    return _git(repo, "ls-tree", "-r", "--name-only", commit).stdout.splitlines()


def commit_date(repo: Path, commit: str) -> str:
    """The committer date of `commit` as strict ISO-8601 / RFC 3339 (`git log -1 --format=%cI`),
    e.g. `2025-03-14T10:22:33+01:00` — the dependency cutoff `uv pip install --exclude-newer=` takes."""
    return _git(repo, "log", "-1", "--format=%cI", commit).stdout.strip()


_SHA = re.compile(r"^[0-9a-f]{7,40}$")
_COMMIT_URL = re.compile(r"/commits?/([0-9a-f]{7,40})(?:[/#?.]|$)")
_PULL_URL = re.compile(r"/pull/(\d+)(?:[/#?]|$)")


def resolve_commits(repo: Path, fix_ref: str) -> Tuple[str, str]:
    """(vuln_commit, fix_commit), both full shas. `fix_ref` is a sha, a `/commit/<sha>` URL or a
    `/pull/<n>` URL (resolved to the merge commit whose subject names `#<n>`, newest first). The
    vulnerable commit is the fix's FIRST parent (for a merge: the base branch before the merge).
    Raises ValueError when the ref does not resolve in the clone (-> `fix_ref_unresolvable`)."""
    repo = Path(repo)
    ref = fix_ref.strip()
    sha: Optional[str] = None
    if _SHA.match(ref):
        sha = ref
    else:
        m = _COMMIT_URL.search(ref)
        if m:
            sha = m.group(1)
        else:
            m = _PULL_URL.search(ref)
            if not m:
                raise ValueError(f"fix ref is neither a sha, a commit URL nor a pull URL: {fix_ref!r}")
            n = m.group(1)
            log = _git(repo, "log", "--all", "--format=%H%x00%s", "-E", "--grep",
                       rf"(#|pull request #){n}([^0-9]|$)", check=False).stdout
            for line in log.splitlines():
                h, _, subj = line.partition("\x00")
                if re.search(rf"(Merge pull request #{n}\b|\(#{n}\))", subj):
                    sha = h
                    break
            if sha is None:
                raise ValueError(f"no merge commit for pull #{n} in the clone")
    r = _git(repo, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}", check=False)
    if r.returncode != 0 or not r.stdout.strip():
        raise ValueError(f"fix commit {sha} is not in the clone")
    fix = r.stdout.strip()
    p = _git(repo, "rev-parse", "--verify", "--quiet", f"{fix}^1", check=False)
    if p.returncode != 0 or not p.stdout.strip():
        raise ValueError(f"fix commit {fix} has no parent")
    return p.stdout.strip(), fix


_TEST_BASENAME = re.compile(r"^(test_.*\.py|.*_test\.py|conftest\.py)$")


def is_test_path(path: str) -> bool:
    """A path is a test when any directory segment is `tests` or `test`, or the basename matches
    `test_*.py` | `*_test.py` | `conftest.py`."""
    p = PurePosixPath(path)
    return any(seg in ("tests", "test") for seg in p.parts[:-1]) or bool(_TEST_BASENAME.match(p.name))


def changed_files(repo: Path, vuln: str, fix: str) -> Tuple[List[str], List[str]]:
    """(non_test_files, test_files) changed between `vuln` and `fix`, each sorted."""
    names = _git(Path(repo), "diff", "--name-only", vuln, fix).stdout.splitlines()
    names = sorted({n for n in names if n})
    return [n for n in names if not is_test_path(n)], [n for n in names if is_test_path(n)]


_LIBS = (("requests", re.compile(r"^\s*(import\s+requests\b|from\s+requests(\.|\s))", re.M)),
         ("httpx", re.compile(r"^\s*(import\s+httpx\b|from\s+httpx(\.|\s))", re.M)),
         ("aiohttp", re.compile(r"^\s*(import\s+aiohttp\b|from\s+aiohttp(\.|\s))", re.M)),
         ("urllib", re.compile(r"^\s*(import\s+urllib(3|\.request)?\b|from\s+urllib(3|\.request)?(\.|\s)|from\s+six\.moves\s+import\s+urllib)", re.M)))


def _library_of_text(text: str) -> str:
    counts = {name: len(rx.findall(text)) for name, rx in _LIBS}
    best = max(counts.items(), key=lambda kv: kv[1])
    return best[0] if best[1] > 0 else "other"


def detect_library(repo: Path, commit: str, files: Sequence[str]) -> str:
    """requests | httpx | aiohttp | urllib | other, by import statements in `files` at `commit`
    (most-imported wins; files absent at `commit` are skipped)."""
    text = "\n".join(_show(Path(repo), commit, f) or "" for f in files)
    return _library_of_text(text)


def _diff(repo: Path, vuln: str, fix: str, paths: Sequence[str]) -> str:
    if not paths:
        return ""
    out = _git(Path(repo), "diff", "--no-color", "--binary", vuln, fix, "--", *paths).stdout
    return out if out.endswith("\n") or not out else out + "\n"


def hidden_patch(repo: Path, vuln: str, fix: str, test_files: Sequence[str]) -> str:
    """`git diff <vuln> <fix> -- <test_files>`: the maintainers' tests, applied only by the verifier."""
    return _diff(repo, vuln, fix, test_files)


def reference_patch(repo: Path, vuln: str, fix: str, fix_files: Sequence[str]) -> str:
    """`git diff <vuln> <fix> -- <fix_files>`: the non-test fix, applied by the oracle agent."""
    return _diff(repo, vuln, fix, fix_files)


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_DIFF_GIT = re.compile(r"^diff --git a/(.*?) b/(.*)$")


def parse_hunks(patch: str) -> Dict[str, List[List[int]]]:
    """{new_path: [[start, end], ...]} from the `@@ -a,b +c,d @@` headers of a unified diff —
    NEW-file line ranges (`d == 0`, a pure deletion, is recorded as `[c, c]`). The recall
    criterion needs them because the verifier has no /solution."""
    out: Dict[str, List[List[int]]] = {}
    current: Optional[str] = None
    for line in patch.splitlines():
        m = _DIFF_GIT.match(line)
        if m:
            current = m.group(2)
            out.setdefault(current, [])
            continue
        if line.startswith("+++ b/"):
            current = line[6:].split("\t", 1)[0]
            out.setdefault(current, [])
            continue
        m = _HUNK.match(line)
        if m and current is not None:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            out[current].append([start, start + max(count, 1) - 1])
    return {k: v for k, v in out.items() if v}


# --------------------------------------------------------------------- test commands

_RUNNABLE_TEST = re.compile(r"^(test_.*\.py|.*_test\.py)$")


def fix_test_argv(test_files: Sequence[str]) -> List[str]:
    """`["python", "-m", "pytest", *<test modules>, "-q", "-p", "no:cacheprovider"]`. Only the
    runnable test modules (`test_*.py` / `*_test.py`) are named — conftest.py and fixture data
    files travel in hidden.patch but are not pytest targets; when no module matches, every `.py`
    test file is named."""
    mods = [f for f in test_files if _RUNNABLE_TEST.match(PurePosixPath(f).name)]
    if not mods:
        mods = [f for f in test_files if f.endswith(".py")] or list(test_files)
    return ["python", "-m", "pytest", *sorted(mods), "-q", "-p", "no:cacheprovider"]


def _tests_dir_at(repo: Path, commit: str) -> str:
    names = _tree(repo, commit)
    tops = {n.split("/", 1)[0] for n in names if "/" in n}
    for d in ("tests", "test"):
        if d in tops:
            return d
    dirs = sorted({str(PurePosixPath(n).parent) for n in names
                   if _RUNNABLE_TEST.match(PurePosixPath(n).name) and "/" in n}, key=lambda d: (d.count("/"), d))
    return dirs[0] if dirs else "tests"


def suite_test_argv(repo: Path, commit: str) -> List[str]:
    """The project's own suite: `["python", "-m", "pytest", <tests dir>, "-q", "-x", "-p", "no:cacheprovider"]`
    with the tests directory detected at `commit` (top-level `tests`/`test`, else the shallowest
    directory holding `test_*.py`, else `tests`)."""
    return ["python", "-m", "pytest", _tests_dir_at(Path(repo), commit), "-q", "-x", "-p", "no:cacheprovider"]


# --------------------------------------------------------------------- python version + recipe

_VER = re.compile(r"\b3\.(\d{1,2})\b")
_UPPER = re.compile(r"(<=?|==|~=)\s*3\.(\d{1,2})(?:\.(\d+|\*))?")
_LOWER = re.compile(r"(>=?|==|~=)\s*3\.(\d{1,2})")


def _fmt(v: Tuple[int, int]) -> str:
    return f"{v[0]}.{v[1]}"


def _clamp(v: Tuple[int, int]) -> Tuple[int, int]:
    return max(PY_MIN, min(PY_MAX, v))


def _requires_spec(repo: Path, commit: str) -> str:
    """The `requires-python`-style specifier found at `commit` (pyproject [project], poetry, setup.cfg, setup.py), or ""."""
    py = _show(repo, commit, "pyproject.toml")
    if py:
        try:
            data = tomllib.loads(py)
        except tomllib.TOMLDecodeError:
            data = {}
        spec = (data.get("project") or {}).get("requires-python")
        if not spec:
            spec = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies", {}).get("python")
        if isinstance(spec, str):
            return spec
    cfg = _show(repo, commit, "setup.cfg")
    if cfg:
        cp = configparser.ConfigParser()
        try:
            cp.read_string(cfg)
            spec = cp.get("options", "python_requires", fallback="")
            if spec:
                return spec
        except configparser.Error:
            pass
    sp = _show(repo, commit, "setup.py")
    if sp:
        m = re.search(r"python_requires\s*=\s*['\"]([^'\"]+)['\"]", sp)
        if m:
            return m.group(1)
    return ""


def _ci_matrix_max(repo: Path, commit: str) -> Optional[Tuple[int, int]]:
    best: Optional[Tuple[int, int]] = None
    for name in _tree(repo, commit):
        if not re.match(r"^\.github/workflows/.*\.ya?ml$", name):
            continue
        text = _show(repo, commit, name) or ""
        for m in re.finditer(r"python-version", text):
            window = text[m.end(): m.end() + 400]
            for v in _VER.finditer(window):
                cand = (3, int(v.group(1)))
                if cand <= PY_MAX and (best is None or cand > best):
                    best = cand
    return best


def _classifier_max(repo: Path, commit: str) -> Optional[Tuple[int, int]]:
    best: Optional[Tuple[int, int]] = None
    for f in ("pyproject.toml", "setup.cfg", "setup.py"):
        for m in re.finditer(r"Programming Language :: Python :: 3\.(\d{1,2})\b", _show(repo, commit, f) or ""):
            cand = (3, int(m.group(1)))
            if cand <= PY_MAX and (best is None or cand > best):
                best = cand
    return best


def _era_cap(repo: Path, commit: str) -> Optional[Tuple[int, int]]:
    date = _git(repo, "log", "-1", "--format=%cs", commit, check=False).stdout.strip()
    if not date:
        return None
    released = [v for v, d in PY_RELEASES.items() if d <= date]
    return max(released) if released else PY_MIN


def python_requires(repo: Path, commit: str) -> str:
    """The newest CPython minor the project allowed at `commit`, as "3.11"-style text.

    Signals, combined: the upper bound of `requires-python` (pyproject `[project]`, poetry,
    `setup.cfg [options]`, `setup.py python_requires=`) when it has one; else the newest version
    named by the CI matrix (`.github/workflows/*.y*ml` `python-version`) or trove classifiers;
    always capped at the newest minor RELEASED before the commit date (`PY_RELEASES`), never
    below the specifier's lower bound, and clamped to `PY_MIN..PY_MAX`. Fallback "3.12" when
    nothing is readable."""
    repo = Path(repo)
    spec = _requires_spec(repo, commit)
    upper: Optional[Tuple[int, int]] = None
    lower: Optional[Tuple[int, int]] = None
    for op, minor, patch in _UPPER.findall(spec):
        v = (3, int(minor))
        if op == "<" and (patch in ("", "*", None) or patch == "0"):
            v = (3, v[1] - 1)
        if op == "~=":
            continue
        upper = v if upper is None else min(upper, v)
    for op, minor in _LOWER.findall(spec):
        v = (3, int(minor))
        lower = v if lower is None else max(lower, v)
    explicit = upper or _ci_matrix_max(repo, commit) or _classifier_max(repo, commit)
    era = _era_cap(repo, commit)
    if explicit is None and era is None:
        return "3.12"
    pick = explicit if explicit is not None else era
    if era is not None and pick > era:
        pick = era
    if lower is not None and pick < lower:
        pick = lower
    return _fmt(_clamp(pick))


_TEST_EXTRAS = ("test", "tests", "testing", "dev", "develop", "all")
_REQ_FILES = re.compile(r"^(requirements/.*\.txt|(dev-|test-|tests-)?requirements([-_](dev|test|tests|testing|ci))?\.txt)$")


def _extras_at(repo: Path, commit: str) -> List[str]:
    names: List[str] = []
    py = _show(repo, commit, "pyproject.toml")
    if py:
        try:
            data = tomllib.loads(py)
            names += list((data.get("project") or {}).get("optional-dependencies") or {})
            names += list(((data.get("tool") or {}).get("poetry") or {}).get("extras") or {})
        except tomllib.TOMLDecodeError:
            pass
    cfg = _show(repo, commit, "setup.cfg")
    if cfg:
        cp = configparser.ConfigParser()
        try:
            cp.read_string(cfg)
            if cp.has_section("options.extras_require"):
                names += list(cp["options.extras_require"])
        except configparser.Error:
            pass
    sp = _show(repo, commit, "setup.py")
    if sp:
        names += re.findall(r"extras_require\s*=\s*\{[^}]*?['\"](\w+)['\"]\s*:", sp)
        names += re.findall(r"['\"](\w+)['\"]\s*:\s*\[", sp)
    return [e for e in _TEST_EXTRAS if e in set(names)]


def _sast_lines(sast_tools: Sequence[str]) -> List[str]:
    """Build-time tool install for the SAST baselines (A4): a separate venv so nothing lands in the
    project's date-pinned env; semgrep's `p/python` ruleset and the CodeQL CLI are FETCHED at build,
    never vendored into this repository (licensing guardrail)."""
    tools = [t.strip().lower() for t in sast_tools if t.strip()]
    if not tools:
        return []
    unknown = sorted(set(tools) - {"semgrep", "bandit", "codeql"})
    if unknown:
        raise ValueError(f"unknown sast tools {unknown}; known: semgrep, bandit, codeql")
    lines: List[str] = []
    venv_pkgs = [t for t in ("semgrep", "bandit") if t in tools]
    if venv_pkgs:
        lines.append(f"uv venv --python 3.12 {SAST_VENV} && uv pip install --python {SAST_VENV}/bin/python {' '.join(venv_pkgs)}")
    if "semgrep" in tools:
        lines.append(f"mkdir -p {SAST_VENV}/rules && {SAST_VENV}/bin/python -c "
                     f"\"import urllib.request as u; u.urlretrieve('https://semgrep.dev/c/p/python', '{SAST_VENV}/rules/p-python.yml')\" "
                     f"&& {SAST_VENV}/bin/semgrep --metrics=off --validate --config {SAST_VENV}/rules/p-python.yml")
    if "codeql" in tools:
        lines.append(f"mkdir -p {CODEQL_DIR} && python -c \"import urllib.request as u, zipfile; "
                     f"u.urlretrieve('https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip', '/tmp/codeql.zip'); "
                     f"zipfile.ZipFile('/tmp/codeql.zip').extractall('{CODEQL_DIR}')\" && chmod -R a+rx {CODEQL_DIR} "
                     f"&& {CODEQL_DIR}/codeql/codeql pack download codeql/python-queries && rm -f /tmp/codeql.zip")
    return lines


INSTALL_MODES = ("uv", "timemachine")
TIMEMACHINE_PORT = 8040


def image_recipe(repo: Path, commit: str, cutoff_date: str, *, sast_tools: Sequence[str] = (),
                 install_mode: str = "uv") -> Tuple[str, List[str]]:
    """(base_image, Dockerfile RUN lines) for the project at `commit`.

    `cutoff_date` is the FIX commit's committer date (`commit_date(repo, fix)`), passed to every
    project install as `uv pip install --system --exclude-newer=<cutoff>` (PEP 700 upload times,
    all of PyPI) so an old commit resolves the dependency set of its own era. Order (SWE-smith's,
    see module docstring): `uv.lock` export, `requirements*.txt`, editable install with the
    test-ish extras found, then pytest. RewardKit goes into its own venv (`REWARDKIT_VENV`) on a
    3.12 interpreter and is NOT date-pinned (it post-dates every fix). `sast_tools` adds `/opt/sast`
    (semgrep, bandit) and `/opt/codeql`; the default is none.

    `install_mode` (A7): "uv" (default) as above; "timemachine" for legacy `setup.py` projects uv
    refuses — the project steps go through `pip` against a local `pypi-timemachine` index proxy
    pinned to the same cutoff date (the proxy runs only during the build step)."""
    if install_mode not in INSTALL_MODES:
        raise ValueError(f"install_mode must be one of {INSTALL_MODES}, got {install_mode!r}")
    repo = Path(repo)
    base = f"python:{python_requires(repo, commit)}-slim"
    tree = _tree(repo, commit)
    top = {n for n in tree if "/" not in n}
    lines = ["pip install --no-cache-dir uv"]
    if install_mode == "timemachine":
        lines.append("pip install --no-cache-dir pypi-timemachine")
        proxy = f"pypi-timemachine {cutoff_date[:10]} --port {TIMEMACHINE_PORT} & sleep 3"
        pin = f"pip install --no-cache-dir --index-url http://127.0.0.1:{TIMEMACHINE_PORT}"
    else:
        pin = f"uv pip install --system --exclude-newer={cutoff_date}"
    steps: List[str] = []
    if "uv.lock" in top:
        steps.append("uv export --frozen --no-hashes --no-emit-project -o /tmp/requirements.lock.txt "
                     f"&& {pin} -r /tmp/requirements.lock.txt")
    for req in sorted(n for n in tree if _REQ_FILES.match(n)):
        steps.append(f"{pin} -r {shlex.quote(req)}")
    if top & {"pyproject.toml", "setup.py", "setup.cfg"}:
        extras = _extras_at(repo, commit)
        target = f".[{','.join(extras)}]" if extras else "."
        steps.append(f"{pin} -e {shlex.quote(target)}")
    steps.append(f"{pin} pytest")
    if install_mode == "timemachine":
        # one RUN: start the proxy, install through it, stop it (nothing listens in the final image)
        lines.append(f"({proxy}; " + " && ".join(steps) + "; rc=$?; kill %1 2>/dev/null; exit $rc)")
    else:
        lines += steps
    lines.append(f"uv venv --python 3.12 {REWARDKIT_VENV} && uv pip install --python {REWARDKIT_VENV}/bin/python "
                 f"harbor-rewardkit=={REWARDKIT_VERSION}")
    lines += _sast_lines(sast_tools)
    return base, lines


_BASE_MINOR = re.compile(r"python:3\.(\d{1,2})-")
#: Debian images under an EOL slim tag (< 3.11) have their apt suites moved to archive.debian.org
#: (A7): rewrite both the classic sources.list and deb822 *.sources before any apt line.
ARCHIVE_APT_FIX = (
    "for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do "
    "[ -f \"$f\" ] && sed -i -e 's|deb.debian.org|archive.debian.org|g' -e 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' "
    "-e 's|security.debian.org|archive.debian.org|g' -e 's/ [a-z]*-updates//g' -e '/-updates /d' \"$f\"; done; "
    "echo 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99archive"
)


def needs_archive_apt(base_image: str) -> bool:
    m = _BASE_MINOR.search(base_image)
    return bool(m) and int(m.group(1)) < 11


def dockerfile(cand: Dict, base_image: str, install: Sequence[str], *, base_digest: Optional[str] = None) -> str:
    """The task image: `base_image` (pinned by digest when `base_digest` is given: `FROM
    python:<minor>-slim@sha256:<digest>`), git via apt (the one apt package; EOL tags get the
    archive.debian.org sources fix first), the project cloned at `cand["vuln_commit"]` from
    `cand["repo_url"]` at BUILD time into /app, the install lines, then a fresh single-commit
    history so no upstream object (and so no later fix) exists in the tree. Mentions the
    vulnerable commit only — never the fix commit."""
    url, sha = cand["repo_url"], cand["vuln_commit"]
    if not sha:
        raise ValueError("dockerfile needs cand['vuln_commit']")
    if base_digest:
        digest = base_digest if base_digest.startswith("sha256:") else f"sha256:{base_digest}"
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError(f"base_digest is not a sha256 digest: {base_digest!r}")
        from_line = f"FROM {base_image}@{digest}"
    else:
        from_line = f"FROM {base_image}"
    lines = [
        "# Generated by evals/calib/build.py — do not edit; rebuild the task instead.",
        from_line,
        "ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 "
        "UV_LINK_MODE=copy UV_NO_CACHE=1",
    ]
    if needs_archive_apt(base_image):
        lines.append(f"RUN {ARCHIVE_APT_FIX}")
    lines += [
        "RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates "
        "&& rm -rf /var/lib/apt/lists/*",
        "# The project at its pinned commit (network at BUILD time only; the task runs with none).",
        f"RUN git clone --quiet {shlex.quote(url)} {calib.WORKDIR} && cd {calib.WORKDIR} "
        f"&& (git cat-file -e {sha}^{{commit}} 2>/dev/null || git fetch --quiet origin {sha}) "
        f"&& git checkout --quiet --detach {sha}",
        f"WORKDIR {calib.WORKDIR}",
    ]
    lines += [f"RUN {step}" for step in install]
    lines += [
        "# Fresh single-commit history: no upstream objects remain, so the tree's own history cannot",
        "# reveal anything after this commit, and the verifier's `git diff` is exactly the agent's edits.",
        "RUN rm -rf .git && git init -q && git add -A "
        "&& git -c user.name=harness -c user.email=harness@local commit -qm task",
        f"RUN mkdir -p {calib.LOGS_ARTIFACTS} {calib.LOGS_VERIFIER} {calib.LOGS_AGENT}",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------- task.toml / instruction

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _toml_key(k: str) -> str:
    return k if _BARE_KEY.match(k) else json.dumps(k, ensure_ascii=False)


def _toml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        if not v:
            return "{}"
        return "{ " + ", ".join(f"{_toml_key(k)} = {_toml_value(x)}" for k, x in v.items()) + " }"
    if v is None:
        return '""'
    raise TypeError(f"not TOML-serialisable: {type(v).__name__}")


#: Record keys that stay out of task.toml [metadata] (mutation-only or redundant with [environment]).
_METADATA_DROP = ("find", "replace", "hidden_test", "container_test", "repo_path")


#: Build facts task.json / task.toml [metadata] carry beyond the Task record (A1, A2, A5, A7).
BUILD_FACT_KEYS = ("fix_hunks", "dependency_cutoff", "base_image", "base_image_digest", "install_mode")


def task_record(task: Task, *, fix_hunks: Optional[Dict[str, List[List[int]]]] = None,
                dependency_cutoff: str = "", review: Optional[Dict[str, int]] = None,
                base_image: str = "", base_image_digest: str = "", install_mode: str = "uv") -> Dict[str, Any]:
    """task.json: `Task.to_record()` plus the build facts the verifier and the card need —
    `fix_hunks`, `dependency_cutoff`, `base_image`, `base_image_digest` ("" when unresolved),
    `install_mode`, `review_underspecified`, `review_test_unfair` (the review pair comes from the
    Task when it has the fields, else from `review`, default -1)."""
    rec: Dict[str, Any] = task.to_record()
    for k in REVIEW_FIELDS:
        rec[k] = int(rec.get(k, (review or {}).get(k, -1)))
    rec["fix_hunks"] = {k: [list(map(int, r)) for r in v] for k, v in (fix_hunks or {}).items()}
    rec["dependency_cutoff"] = dependency_cutoff
    rec["base_image"] = base_image
    rec["base_image_digest"] = base_image_digest or ""
    rec["install_mode"] = install_mode
    return rec


def task_toml(task: Task, *, record: Optional[Dict[str, Any]] = None) -> str:
    """The exact CONTRACTS.md layout: header (schema_version, source, artifacts), [task],
    [metadata] (= `record` or `task_record(task)` minus `_METADATA_DROP`, `suite_test` as argv),
    [environment], [agent], [verifier]. Round-trips through `tomllib`."""
    rec = dict(record if record is not None else task_record(task))
    for k in _METADATA_DROP:
        rec.pop(k, None)
    rec["suite_test"] = shlex.split(task.suite_test) if isinstance(task.suite_test, str) else list(task.suite_test)
    rec["eval_id"] = task.eval_id
    rec["canary"] = task.canary
    out = [
        f'schema_version = {_toml_value(calib.TASK_TOML_SCHEMA_VERSION)}',
        'source = "security-agents/evals/calib"',
        f'artifacts = [{_toml_value(calib.WORKDIR)}]',
        "",
        "[task]",
        f"name = {_toml_value(f'{calib.TASK_ORG}/{task.task_id}')}",
        f"description = {_toml_value(task.description)}",
        'keywords = ["security"]',
        "",
        "[metadata]",
    ]
    out += [f"{_toml_key(k)} = {_toml_value(v)}" for k, v in rec.items()]
    out += [
        "",
        "[environment]",
        'network_mode = "no-network"',
        f"workdir = {_toml_value(calib.WORKDIR)}",
        "cpus = 2",
        "memory_mb = 2048",
        "build_timeout_sec = 1800",
        "",
        "[agent]",
        'network_mode = "no-network"',
        "timeout_sec = 1800",
        "",
        "[verifier]",
        'environment_mode = "separate"',
        'network_mode = "no-network"',
        "timeout_sec = 1200",
    ]
    text = "\n".join(out) + "\n"
    tomllib.loads(text)        # never emit something Harbor cannot parse
    return text


_INSTRUCTION = (
    "Review this repository at {workdir} for security vulnerabilities. Fix what you find with minimal, "
    "targeted edits; do not refactor unrelated code; do not add or modify files under tests/ except "
    "to add a regression test for a fix. Run the project's test suite (`{suite}`) after editing. "
    "When done, write a JSON report to {report} with keys: agent, property (one of "
    "P0–P9), repo, commit, findings[{{id, file, line, evidence, status}}], claims[{{statement, oracle, "
    "evidence}}], where each oracle is a command runnable from {workdir} that exits 0 iff the claim holds. "
    "Keep all descriptions categorical.\n"
)


def instruction_text(task: Task) -> str:
    """The one generic instruction (CONTRACTS.md), parametrised only by the project's suite command.
    No advisory text, class, property or CWE: the enumeration `P0–P9` is named, never which applies."""
    suite = shlex.join(task.container_test) if task.container_test else task.suite_test
    return _INSTRUCTION.format(workdir=calib.WORKDIR, suite=suite, report=calib.REPORT_ARTIFACT)


# --------------------------------------------------------------------- the task directory

def _write(path: Path, text: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _stub_test_sh() -> str:
    return "\n".join([
        "#!/usr/bin/env bash",
        STUB_MARKER,
        "# Rebuild this task (calib-build) once W-C's verifier assets exist. Exits 2 so Harbor never reads a reward from it.",
        'echo "verifier not vendored into this task: rebuild it" >&2',
        "exit 2",
    ]) + "\n"


def _vendor_verifier(tests_dir: Path, assets: Optional[Path]) -> bool:
    """Copy W-C's `verifier_assets/` tree and the sibling `verify.py` into `tests_dir`. Returns
    whether the real verifier was vendored; otherwise a stub test.sh (exit 2) is written."""
    assets = Path(assets) if assets is not None else VERIFIER_ASSETS_DIR
    tests_dir.mkdir(parents=True, exist_ok=True)
    if assets.is_dir() and (assets / "test.sh").is_file():
        shutil.copytree(assets, tests_dir, dirs_exist_ok=True, symlinks=False)
        verify_py = assets.parent / "verify.py"          # evals/calib/verify.py sits next to verifier_assets/
        if verify_py.is_file():
            shutil.copy2(verify_py, tests_dir / "verify.py")
        sh = tests_dir / "test.sh"
        sh.chmod(sh.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True
    _write(tests_dir / "test.sh", _stub_test_sh(), executable=True)
    return False


def verifier_vendored(task_dir: Path) -> bool:
    """False when the task's tests/test.sh is the build-time stub (or missing)."""
    sh = Path(task_dir) / "tests" / "test.sh"
    if not sh.is_file():
        return False
    return STUB_MARKER not in sh.read_text()


def write_task_dir(task: Task, *, task_dir: Path, dockerfile_text: str, reference: str,
                   hidden: Optional[str], record: Dict[str, Any], verify_source: Optional[Path] = None) -> bool:
    """Write every file of the Harbor task dir (replacing an older build). `hidden is None` on
    negatives (no tests/hidden.patch). Returns `verifier_vendored`."""
    task_dir = Path(task_dir)
    if task_dir.exists():
        shutil.rmtree(task_dir)
    task_dir.mkdir(parents=True)
    _write(task_dir / "instruction.md", instruction_text(task))
    _write(task_dir / "task.toml", task_toml(task, record=record))
    rec_json = json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    _write(task_dir / "task.json", rec_json)
    _write(task_dir / "environment" / "Dockerfile", dockerfile_text)
    _write(task_dir / "solution" / "solve.sh",
           "#!/usr/bin/env bash\nset -euo pipefail\n"
           f"cd {calib.WORKDIR} && git apply --index {calib.SOLUTION_DIR}/reference.patch\n", executable=True)
    _write(task_dir / "solution" / "reference.patch", reference)
    vendored = _vendor_verifier(task_dir / "tests", verify_source)
    _write(task_dir / "tests" / "task.json", rec_json)
    if hidden is not None:
        _write(task_dir / "tests" / "hidden.patch", hidden)
    return vendored


def load_base_digests(path: Path = CALIB_REPOS_FILE) -> Dict[str, str]:
    """`base_digests: {tag: sha256 digest}` from repos.yaml (filled by `calib-build --resolve-digests`,
    W-D's flag; empty until then). Unknown tag -> no digest -> the Dockerfile pins the tag only."""
    path = Path(path)
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text()) or {}
    return {str(k): str(v) for k, v in (data.get("base_digests") or {}).items() if v}


def _append_calib_repo(path: Path, task: Task, base_image: str, install: Sequence[str]) -> None:
    """Add (or replace) the task's entry in evals/calib/repos.yaml, keeping the header comment and
    the `base_digests` table."""
    path = Path(path)
    text = path.read_text() if path.exists() else ""
    header = "".join(ln for ln in text.splitlines(keepends=True) if ln.startswith("#"))
    data = yaml.safe_load(text) if text.strip() else None
    data = data or {}
    repos = data.get("repos") or {}
    repos[task.task_id] = {
        "url": task.repo_url,
        "local_path": f".cache/calib/{task.task_id}",
        "commit": task.commit,
        "visibility": "public",
        "image": {"base": base_image, "install": list(install)},
    }
    out: Dict[str, Any] = {"base_digests": data.get("base_digests") or {}, "repos": dict(sorted(repos.items()))}
    body = yaml.safe_dump(out, sort_keys=False, default_flow_style=False, width=1000)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(header + ("\n" if header else "") + body)


def task_dir_rel(tasks_dir: Path, task_id: str) -> str:
    """Repo-relative task dir for the record; the canonical `evals/calib/egress/tasks/<id>` when
    `tasks_dir` is not under the toolkit repo (test builds in tmp)."""
    try:
        rel = Path(tasks_dir).resolve().relative_to(calib.REPO)
        return f"{rel.as_posix()}/{task_id}"
    except ValueError:
        return f"{calib.TASKS_DIR.relative_to(calib.REPO).as_posix()}/{task_id}"


def _fix_ref(cand: Dict) -> str:
    if cand.get("fix_commit"):
        return str(cand["fix_commit"])
    for ref in cand.get("fix_refs") or []:
        if _COMMIT_URL.search(ref) or _PULL_URL.search(ref):
            return ref
    return ""


def clone_candidate(url: str, commit: str, dest: Path, *, name: str) -> Path:
    """`repos.clone_at` on a RepoConfig built from the candidate (read-only git; the local-checkout
    shortcut never matches `.cache/calib/<id>`). A fresh clone every time: an older one is removed."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    cfg = RepoConfig(name=name, url=url, local_path=f".cache/calib/{name}", commit=commit or "HEAD")
    return clone_at(cfg, dest)


def _count_py(repo: Path, commit: str) -> int:
    return sum(1 for n in _tree(repo, commit) if n.endswith(".py"))


def _review(cand: Dict) -> Dict[str, int]:
    out = {}
    for k in REVIEW_FIELDS:
        try:
            out[k] = int(cand.get(k, -1))
        except (TypeError, ValueError):
            out[k] = -1
    return out


def build_task(cand: Dict, *, work: Path, tasks_dir: Path = TASKS_DIR, canary: str,
               verify_source: Optional[Path] = None, size_limit_py_files: int = 3000,
               repos_file: Path = CALIB_REPOS_FILE, sast_tools: Sequence[str] = ()) -> Tuple[Optional[Task], Optional[str]]:
    """One candidate -> `(task, None)` with its task dir written under `tasks_dir`, or
    `(None, reason)` with a reason from `evals.calib.EXCLUSION_REASONS`.

    Funnel order: `no_fix_ref` -> clone -> `fix_ref_unresolvable` -> `not_python_project` ->
    `repo_too_large` -> `no_test_in_fix` (we never author hidden tests) -> `other` (a fix that
    changes tests only). `verify_source` is W-C's `verifier_assets/` dir (default
    `evals/calib/verifier_assets/`; its sibling `verify.py` is copied too); when absent the task
    gets a stub test.sh and `verifier_vendored(task_dir)` is False. `repos_file` receives one
    entry per built task (tests point it into tmp) and supplies `base_digests` (A7). The
    candidate's optional `install_mode` ("uv" default | "timemachine") selects the recipe."""
    ghsa = str(cand.get("ghsa_id") or "").strip()
    if not ghsa:
        raise ValueError("candidate has no ghsa_id")
    task_id = f"{calib.PROPERTY}-{ghsa.lower()}"
    ref = _fix_ref(cand)
    if not ref:
        return None, "no_fix_ref"
    work = Path(work)
    m = _COMMIT_URL.search(ref)
    sha_hint = ref if _SHA.match(ref) else (m.group(1) if m else "")
    try:
        repo = clone_candidate(str(cand["repo_url"]), sha_hint, work / task_id, name=task_id)
    except subprocess.CalledProcessError:
        return None, "fix_ref_unresolvable"
    try:
        vuln, fix = resolve_commits(repo, ref)
    except ValueError:
        return None, "fix_ref_unresolvable"
    _git(repo, "checkout", "--quiet", "--detach", vuln)

    n_py = _count_py(repo, vuln)
    if n_py == 0:
        return None, "not_python_project"
    if n_py > size_limit_py_files:
        return None, "repo_too_large"
    fix_files, test_files = changed_files(repo, vuln, fix)
    if not test_files:
        return None, "no_test_in_fix"
    if not fix_files:
        return None, "other"       # the fix commit changes tests only; nothing to find

    cwes = cand.get("cwe") or []
    cwe = calib.CWE if calib.CWE in cwes or not cwes else str(cwes[0])
    library = str(cand.get("library") or "") or detect_library(repo, vuln, fix_files)
    suite = suite_test_argv(repo, vuln)
    cutoff = commit_date(repo, fix)
    install_mode = str(cand.get("install_mode") or "uv")
    base_image, install = image_recipe(repo, vuln, cutoff, sast_tools=sast_tools, install_mode=install_mode)
    base_digest = load_base_digests(Path(repos_file)).get(base_image, "")
    reference = reference_patch(repo, vuln, fix, fix_files)
    hidden = hidden_patch(repo, vuln, fix, test_files)
    review = _review(cand)
    fields: Dict[str, Any] = dict(
        task_id=task_id, eval_id=calib.EVAL_ID, repo=task_id, repo_url=str(cand["repo_url"]), commit=vuln,
        property=calib.PROPERTY,
        description=str(cand.get("summary_category") or "outbound request destination not restricted"),
        file=fix_files[0], find="", replace="", hidden_test=shlex.join(suite), suite_test=shlex.join(suite),
        container_test=list(suite), pythonpath=[], agent="agents/egress.md", canary=canary,
        source=SOURCE_ADVISORY, kind=KIND_ADVISORY, is_negative=False, advisory_id=ghsa, cwe=cwe,
        project=str(cand.get("project") or ""), vuln_commit=vuln, fix_commit=fix, fix_files=fix_files,
        scope_files=scope_files(repo, vuln, fix_files), hidden_patch="tests/hidden.patch",
        fix_test=fix_test_argv(test_files), fp_files=[], sub_scenario=str(cand.get("sub_scenario") or "other"),
        library=library, disclosure_date=str(cand.get("disclosure_date") or ""), split="", anchor=False,
        oracle2=[], scope_rule=SCOPE_REACHABLE_FROM_FIX, contamination={},
        task_dir=task_dir_rel(tasks_dir, task_id),
    )
    fields.update({k: v for k, v in review.items() if k in _TASK_FIELDS})
    task = Task(**fields)
    record = task_record(task, fix_hunks=parse_hunks(reference), dependency_cutoff=cutoff, review=review,
                         base_image=base_image, base_image_digest=base_digest, install_mode=install_mode)
    write_task_dir(task, task_dir=Path(tasks_dir) / task_id,
                   dockerfile_text=dockerfile({"repo_url": task.repo_url, "vuln_commit": vuln}, base_image, install,
                                              base_digest=base_digest or None),
                   reference=reference, hidden=hidden, record=record, verify_source=verify_source)
    _append_calib_repo(Path(repos_file), task, base_image, install)
    return task, None


def _default_canary() -> str:
    return (calib.REPO / "evals" / "registry" / "CANARY.txt").read_text().strip()


def build_all(cands: Iterable[Dict], *, work: Path, dry_run: bool = False, log=print, **build_kwargs) -> Dict:
    """The selection funnel over `cands` (W-A candidate dicts). Returns
    `{"dry_run", "total", "built", "excluded": {reason: n}, "tasks": [Task], "task_ids",
    "exclusions": [{ghsa_id, project, reason, note}], "verifier_vendored": bool, "vendored": {task_id: bool}}`
    and prints the funnel through `log`. `dry_run` clones and classifies but writes only under
    `work/dry-run/` (never the repo's tasks dir, repos.yaml or exclusions.jsonl). Extra keyword
    arguments go to `build_task` (`tasks_dir`, `canary`, `verify_source`, `size_limit_py_files`,
    `repos_file`, `sast_tools`); `exclusions_file` (default `EXCLUSIONS_FILE`, None to skip) is
    rewritten with every exclusion of this run."""
    work = Path(work)
    exclusions_file = build_kwargs.pop("exclusions_file", EXCLUSIONS_FILE)
    if dry_run:
        build_kwargs["tasks_dir"] = work / "dry-run" / "tasks"
        build_kwargs["repos_file"] = work / "dry-run" / "repos.yaml"
        exclusions_file = None
    build_kwargs.setdefault("canary", _default_canary())
    tasks_dir = Path(build_kwargs.get("tasks_dir", TASKS_DIR))
    tasks: List[Task] = []
    excluded: Dict[str, int] = {}
    exclusions: List[Dict[str, str]] = []
    vendored: Dict[str, bool] = {}
    total = 0
    for cand in cands:
        total += 1
        note = ""
        try:
            task, reason = build_task(cand, work=work, **build_kwargs)
        except Exception as e:                      # one bad candidate never stops the funnel
            task, reason, note = None, "other", f"{type(e).__name__}: {e}"
        if task is not None:
            tasks.append(task)
            vendored[task.task_id] = verifier_vendored(tasks_dir / task.task_id)
            continue
        reason = reason if reason in calib.EXCLUSION_REASONS else "other"
        excluded[reason] = excluded.get(reason, 0) + 1
        exclusions.append({"ghsa_id": str(cand.get("ghsa_id", "")), "project": str(cand.get("project", "")),
                           "reason": reason, "note": note})
    result = {"dry_run": dry_run, "total": total, "built": len(tasks),
              "excluded": dict(sorted(excluded.items())), "tasks": tasks, "task_ids": [t.task_id for t in tasks],
              "exclusions": exclusions, "verifier_vendored": bool(tasks) and all(vendored.values()),
              "vendored": vendored}
    log(f"calib-build funnel{' (dry run)' if dry_run else ''}: {total} candidates")
    log(f"  {'built':<24}{len(tasks):>5}")
    for reason, n in result["excluded"].items():
        log(f"  {reason:<24}{n:>5}")
    log(f"  verifier_vendored: {'true' if result['verifier_vendored'] else 'false'}")
    if exclusions_file is not None and not dry_run:
        p = Path(exclusions_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("".join(json.dumps(x, sort_keys=True) + "\n" for x in exclusions))
    return result


def write_tasks_jsonl(tasks: Sequence[Task], path: Path = TASKS_JSONL) -> None:
    """One `Task.to_record()` per line (sorted keys), so `Task(**json.loads(line))` round-trips."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(t.to_record(), sort_keys=True, ensure_ascii=False) + "\n" for t in tasks))


def load_calib_repos(path: Path = CALIB_REPOS_FILE) -> Dict[str, RepoConfig]:
    """`repos.load_repos(path)`: one RepoConfig per built task (key = task_id), `image.base` honoured."""
    return load_repos(Path(path))
