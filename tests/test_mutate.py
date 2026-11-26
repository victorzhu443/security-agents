"""Tests OF the mutation runner (evals/mutate.py), not mutations of anything.

A tiny git repo is built in tmp_path: one module, one test that pins one of its
two checks, and mutations that revert each.  No network; the interpreter is the
one running pytest."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from evals import mutate

MODULE = '''\
import hmac

def check_token(given, expected):
    return hmac.compare_digest(given, expected)

def allowed_host(host):
    return host in {"api.example.com"}
'''

TEST = '''\
from guard import check_token

def test_token_uses_constant_time_compare():
    import guard, inspect
    assert "compare_digest" in inspect.getsource(guard.check_token)
    assert check_token("a", "a") and not check_token("a", "b")
'''


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


@pytest.fixture
def tiny_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "proj"
    (repo / "tests").mkdir(parents=True)
    (repo / "security").mkdir()
    (repo / "guard.py").write_text(MODULE)
    (repo / "tests" / "test_guard.py").write_text(TEST)
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _spec(mutations, test=None):
    return {"test": test or f"{sys.executable} -m pytest tests -q -x -p no:cacheprovider",
            "mutations": mutations}


def _write(repo: Path, spec) -> Path:
    p = repo / "security" / "mutations.yaml"
    p.write_text(yaml.safe_dump(spec))
    return p


KILLED = {"id": "P5-token-eq", "property": "P5", "file": "guard.py",
          "description": "== instead of compare_digest",
          "find": "hmac.compare_digest(given, expected)", "replace": "given == expected"}
SURVIVED = {"id": "P4-host-allowlist", "property": "P4", "file": "guard.py",
            "description": "drop the host allow-list",
            "find": 'host in {"api.example.com"}', "replace": "True"}


def test_kill_rate_and_survivor_id(tiny_repo, tmp_path):
    spec_path = _write(tiny_repo, _spec([KILLED, SURVIVED]))
    out = tmp_path / "res.json"
    rc = mutate.main(["--repo", str(tiny_repo), "--mutations", str(spec_path), "--out", str(out), "--quiet"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["baseline"]["passed"] is True
    s = data["summary"]
    assert s["_overall"] == {"mutations": 2, "killed": 1, "survived": 1, "errors": 0, "kill_rate": 0.5}
    assert s["P5"]["kill_rate"] == 1.0 and s["P4"]["kill_rate"] == 0.0
    by_id = {m["id"]: m for m in data["mutations"]}
    assert by_id["P5-token-eq"]["result"] == "killed"
    assert by_id["P4-host-allowlist"]["result"] == "survived"
    assert "passed" in by_id["P4-host-allowlist"]["detail"]      # test tail kept for survivors
    md = out.with_suffix(".md").read_text()
    assert "P4-host-allowlist" in md and "SURVIVED" in md and "Kill rate 0.5" in md


def test_strict_exits_nonzero_on_survivor(tiny_repo, tmp_path):
    spec_path = _write(tiny_repo, _spec([KILLED, SURVIVED]))
    assert mutate.main(["--repo", str(tiny_repo), "--mutations", str(spec_path),
                        "--out", str(tmp_path / "r.json"), "--quiet", "--strict"]) == 1
    spec_path = _write(tiny_repo, _spec([KILLED]))
    assert mutate.main(["--repo", str(tiny_repo), "--mutations", str(spec_path),
                        "--out", str(tmp_path / "r2.json"), "--quiet", "--strict"]) == 0


def test_find_count_guard_errors_on_ambiguous_and_missing_find(tiny_repo, tmp_path):
    ambiguous = {"id": "amb", "property": "P1", "file": "guard.py",
                 "find": "def ", "replace": "def x_"}                  # occurs twice
    missing = {"id": "miss", "property": "P1", "file": "guard.py",
               "find": "no such text", "replace": "whatever"}
    noop = {"id": "noop", "property": "P1", "file": "guard.py",
            "find": "import hmac", "replace": "import hmac"}
    spec_path = _write(tiny_repo, _spec([ambiguous, missing, noop]))
    out = tmp_path / "res.json"
    rc = mutate.main(["--repo", str(tiny_repo), "--mutations", str(spec_path), "--out", str(out), "--quiet"])
    assert rc == 0
    data = json.loads(out.read_text())
    by_id = {m["id"]: m for m in data["mutations"]}
    assert by_id["amb"]["result"] == "error" and "occurs 2 times" in by_id["amb"]["detail"]
    assert by_id["miss"]["result"] == "error" and "occurs 0 times" in by_id["miss"]["detail"]
    assert by_id["noop"]["result"] == "error" and "no-op" in by_id["noop"]["detail"]
    assert data["summary"]["_overall"]["errors"] == 3
    assert data["summary"]["_overall"]["kill_rate"] == 0.0


def test_target_tree_is_never_modified_and_worktrees_are_removed(tiny_repo, tmp_path):
    before = (tiny_repo / "guard.py").read_text()
    spec_path = _write(tiny_repo, _spec([KILLED, SURVIVED]))
    mutate.main(["--repo", str(tiny_repo), "--mutations", str(spec_path),
                 "--out", str(tmp_path / "r.json"), "--quiet"])
    assert (tiny_repo / "guard.py").read_text() == before
    wts = subprocess.run(["git", "-C", str(tiny_repo), "worktree", "list", "--porcelain"],
                         capture_output=True, text=True, check=True).stdout
    assert wts.count("worktree ") == 1          # only the main tree remains


def test_red_baseline_aborts(tiny_repo, tmp_path):
    (tiny_repo / "tests" / "test_guard.py").write_text("def test_red():\n    assert False\n")
    _git(tiny_repo, "commit", "-qam", "break the suite")
    spec_path = _write(tiny_repo, _spec([KILLED]))
    out = tmp_path / "r.json"
    rc = mutate.main(["--repo", str(tiny_repo), "--mutations", str(spec_path), "--out", str(out), "--quiet"])
    assert rc == 2 and not out.exists()


def _fake_venv(repo: Path) -> Path:
    """A gitignored-style `.venv/bin/python` that runs this test's interpreter."""
    fake = repo / ".venv" / "bin"
    fake.mkdir(parents=True)
    py = fake / "python"
    py.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    py.chmod(0o755)
    return py


def test_relative_interpreter_resolves_against_the_target_repo(tiny_repo):
    # venvs are gitignored: `.venv/bin/python` only exists in the main tree
    _fake_venv(tiny_repo)
    argv = mutate.resolve_command(".venv/bin/python -m pytest tests", tiny_repo)
    assert argv[0] == os.path.abspath(tiny_repo / ".venv" / "bin" / "python")   # not the symlink target
    assert argv[1:] == ["-m", "pytest", "tests"]


def test_linked_worktree_resolves_interpreter_and_name_from_main_checkout(tiny_repo, tmp_path):
    _fake_venv(tiny_repo)
    linked = tmp_path / "linked-wt"
    _git(tiny_repo, "worktree", "add", "--detach", "-q", str(linked), "HEAD")
    try:
        assert mutate.main_checkout(linked).resolve() == tiny_repo.resolve()
        argv = mutate.resolve_command(".venv/bin/python -m pytest", linked)
        assert argv[0] == os.path.abspath(tiny_repo / ".venv" / "bin" / "python")
        with pytest.raises(FileNotFoundError):
            mutate.resolve_command("./nope/python -m pytest", linked)
        (linked / "security").mkdir()
        spec_path = _write(linked, _spec([KILLED], test=".venv/bin/python -m pytest tests -q -x -p no:cacheprovider"))
        _git(linked, "add", "-A"); _git(linked, "commit", "-qm", "spec")
        out = tmp_path / "r.json"
        assert mutate.main(["--repo", str(linked), "--mutations", str(spec_path), "--out", str(out), "--quiet"]) == 0
        assert json.loads(out.read_text())["repo"] == tiny_repo.name
    finally:
        _git(tiny_repo, "worktree", "remove", "--force", str(linked))


def test_spec_validation(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump({"mutations": [{"id": "a", "property": "P1", "file": "f",
                                                "find": "x", "replace": "y"}]}))
    with pytest.raises(mutate.MutationSpecError, match="no test command"):
        mutate.load_spec(p)
    p.write_text(yaml.safe_dump({"test": "true", "mutations": [
        {"id": "a", "property": "P1", "file": "f", "find": "x", "replace": "y"},
        {"id": "a", "property": "P1", "file": "f", "find": "x", "replace": "z"}]}))
    with pytest.raises(mutate.MutationSpecError, match="duplicate"):
        mutate.load_spec(p)
    p.write_text(yaml.safe_dump({"test": "true", "mutations": [{"id": "a", "property": "P1"}]}))
    with pytest.raises(mutate.MutationSpecError, match="missing"):
        mutate.load_spec(p)
