"""Tests of evals/agent/tasks.py: catalogue text -> Task records, and the test-command map.

Everything runs on a fixture catalogue and a hand-built RepoConfig whose local checkout does
not exist; no network, no docker, no model. The one integration test reads the four real
catalogues through `repos.catalogue_text` (a read-only `git show` on the local checkouts)
and is skipped when any checkout or its pinned commit is absent, so it can never clone."""
import json
from pathlib import Path

import pytest

from evals import registry
from evals.agent import repos, tasks
from evals.agent.repos import RepoConfig
from evals.agent.types import SOURCE_REAL_CODEBASE, Task

FIXTURE_YAML = """\
test: ".venv/bin/python -m pytest tests/security -q -x -p no:cacheprovider"
pythonpath: [".", "scripts"]
mutations:
  - id: P4-fetch-no-allowlist
    property: P4
    description: drop the host allow-list from safe_fetch
    file: scripts/safe_http.py
    find: "if host not in ALLOWED_HOSTS:"
    replace: "if False:"
  - id: P2-redact-ambiguous-prefix
    property: P2
    description: reintroduce the ambiguous whitespace prefix in the cookie regex
    file: scripts/redact.py
    find: "[ \\\\t]*(?:-[ \\\\t]*)?"
    replace: "[ \\\\t]*-?[ \\\\t]*"
    test: ".venv/bin/python -m pytest tests/security/test_redact.py -q -p no:cacheprovider"
  - id: P9-sha1-security-default
    property: P9
    description: sha1 without usedforsecurity=False
    file: scripts/adapters.py
    find: "hashlib.sha1(data, usedforsecurity=False)"
    replace: "hashlib.sha1(data)"
"""

CFG = RepoConfig(name="fixture-repo", url="https://example.invalid/x.git",
                 local_path="does-not-exist", commit="a" * 40)


@pytest.fixture(autouse=True)
def _no_local_checkouts(monkeypatch, tmp_path):
    """Point the repos root at an empty dir so `local_checkout` is None for the fixture."""
    monkeypatch.setenv("SA_REPOS_ROOT", str(tmp_path / "projects"))


@pytest.fixture
def fixture_tasks():
    return tasks.load_tasks(CFG, catalogue_text=FIXTURE_YAML)


# --------------------------------------------------------------------- mapping table

@pytest.mark.parametrize("cmd,expected", [
    (".venv/bin/python -m pytest tests/security -q -x -p no:cacheprovider",
     ["python", "-m", "pytest", "tests/security", "-q", "-x", "-p", "no:cacheprovider"]),
    (".venv-sec/bin/python -m pytest tests/security -q -x -p no:cacheprovider",
     ["python", "-m", "pytest", "tests/security", "-q", "-x", "-p", "no:cacheprovider"]),
    ("/Users/vzhu/Developer/projects/study-hub/.venv-sec/bin/python -m pytest tests/security -q -x -p no:cacheprovider",
     ["python", "-m", "pytest", "tests/security", "-q", "-x", "-p", "no:cacheprovider"]),
    ("python3 -m pytest tests -q", ["python", "-m", "pytest", "tests", "-q"]),
    ("python3.12 -m pytest tests -q", ["python", "-m", "pytest", "tests", "-q"]),
    ("/usr/local/bin/python3 -m pytest", ["python", "-m", "pytest"]),
])
def test_map_test_command_interpreter_forms(cmd, expected):
    assert tasks.map_test_command(cmd) == expected


def test_map_test_command_leaves_non_interpreters_alone():
    assert tasks.map_test_command("pytest tests/security -q") == ["pytest", "tests/security", "-q"]
    assert tasks.map_test_command("make security-test") == ["make", "security-test"]
    # a binary that merely lives next to python is not python
    assert tasks.map_test_command(".venv/bin/pytest -q")[0] == ".venv/bin/pytest"


def test_map_test_command_keeps_quoting():
    assert tasks.map_test_command('.venv/bin/python -m pytest -k "a and b"') == \
        ["python", "-m", "pytest", "-k", "a and b"]


def test_map_test_command_empty_raises():
    with pytest.raises(ValueError):
        tasks.map_test_command("   ")


def test_is_interpreter_token():
    assert tasks.is_interpreter_token("python")
    assert tasks.is_interpreter_token("python3.11")
    assert tasks.is_interpreter_token("bin/python")
    assert tasks.is_interpreter_token("/opt/venv/bin/pythonw")
    assert not tasks.is_interpreter_token("pythonic")
    assert not tasks.is_interpreter_token("scripts/python/run.sh")
    assert not tasks.is_interpreter_token("pytest")


# --------------------------------------------------------------------- load_tasks

def test_load_tasks_shape(fixture_tasks):
    assert [t.task_id for t in fixture_tasks] == [
        "P4-fetch-no-allowlist", "P2-redact-ambiguous-prefix", "P9-sha1-security-default"]
    t = fixture_tasks[0]
    assert isinstance(t, Task)
    assert t.eval_id == "security.agent.fixture-repo.v1"
    assert t.repo == "fixture-repo"
    assert t.repo_url == "https://example.invalid/x.git"
    assert t.commit == "a" * 40
    assert t.property == "P4"
    assert t.agent == "agents/egress.md"
    assert t.source == SOURCE_REAL_CODEBASE == "real-codebase"
    assert t.canary == registry.canary()
    assert t.file == "scripts/safe_http.py"
    assert t.find == "if host not in ALLOWED_HOSTS:"
    assert t.replace == "if False:"
    assert t.pythonpath == [".", "scripts"]
    assert t.repo_path is None
    assert t.description.startswith("drop the host allow-list")


def test_load_tasks_test_commands(fixture_tasks):
    suite = ".venv/bin/python -m pytest tests/security -q -x -p no:cacheprovider"
    default, override, _ = fixture_tasks
    assert default.suite_test == suite
    assert default.hidden_test == suite
    assert default.container_test == ["python", "-m", "pytest", "tests/security", "-q", "-x", "-p", "no:cacheprovider"]
    assert override.hidden_test == ".venv/bin/python -m pytest tests/security/test_redact.py -q -p no:cacheprovider"
    assert override.suite_test == suite
    assert override.container_test[0] == "python"
    assert override.container_test[3] == "tests/security/test_redact.py"
    assert all(t.container_test[0] == "python" for t in fixture_tasks)


def test_load_tasks_agents_per_property(fixture_tasks):
    assert {t.property: t.agent for t in fixture_tasks} == {
        "P4": "agents/egress.md", "P2": "agents/cost.md", "P9": "agents/hardening.md"}


def test_load_tasks_unknown_property_raises():
    bad = FIXTURE_YAML.replace("property: P9", "property: PX")
    with pytest.raises(ValueError) as ei:
        tasks.load_tasks(CFG, catalogue_text=bad)
    assert "P9-sha1-security-default" in str(ei.value)
    assert "PX" in str(ei.value)


def test_load_tasks_malformed_catalogue_raises():
    from evals.mutate import MutationSpecError
    with pytest.raises(MutationSpecError):
        tasks.load_tasks(CFG, catalogue_text="mutations: []\n")


def test_load_tasks_uses_catalogue_text_not_git(monkeypatch):
    def boom(cfg, cache_dir=None):
        raise AssertionError("catalogue_text must not be consulted when text is given")
    monkeypatch.setattr(repos, "catalogue_text", boom)
    assert len(tasks.load_tasks(CFG, catalogue_text=FIXTURE_YAML)) == 3


def test_load_tasks_reads_catalogue_via_repos_when_no_text(monkeypatch):
    calls = []

    def fake(cfg, cache_dir=None):
        calls.append(cfg.name)
        return FIXTURE_YAML
    monkeypatch.setattr(repos, "catalogue_text", fake)
    assert len(tasks.load_tasks(CFG)) == 3
    assert calls == ["fixture-repo"]


def test_load_tasks_repo_path_when_checkout_exists(monkeypatch, tmp_path):
    root = tmp_path / "projects"
    (root / "does-not-exist" / ".git").mkdir(parents=True)
    monkeypatch.setenv("SA_REPOS_ROOT", str(root))
    t = tasks.load_tasks(CFG, catalogue_text=FIXTURE_YAML)[0]
    assert t.repo_path == str(root / "does-not-exist")


def test_load_tasks_registry_override():
    class R:
        @staticmethod
        def canary():
            return "CANARY-OVERRIDE"
    t = tasks.load_tasks(CFG, catalogue_text=FIXTURE_YAML, registry=R)[0]
    assert t.canary == "CANARY-OVERRIDE"


# --------------------------------------------------------------------- load_all_tasks

def test_load_all_tasks_selects_repos(monkeypatch):
    repo_map = {
        "alpha": RepoConfig(name="alpha", url="https://example.invalid/a.git", local_path="a", commit="b" * 40),
        "beta": RepoConfig(name="beta", url="https://example.invalid/b.git", local_path="b", commit="c" * 40),
    }
    monkeypatch.setattr(repos, "catalogue_text", lambda cfg, cache_dir=None: FIXTURE_YAML)
    out = tasks.load_all_tasks("all", repos=repo_map)
    assert list(out) == ["alpha", "beta"]
    assert out["beta"][0].eval_id == "security.agent.beta.v1"
    assert list(tasks.load_all_tasks("beta", repos=repo_map)) == ["beta"]
    with pytest.raises(ValueError):
        tasks.load_all_tasks("gamma", repos=repo_map)


# --------------------------------------------------------------------- filter / jsonl

def test_filter_tasks_by_id_and_property(fixture_tasks):
    ids = lambda ts: [t.task_id for t in ts]  # noqa: E731
    assert ids(tasks.filter_tasks(fixture_tasks, None)) == ids(fixture_tasks)
    assert ids(tasks.filter_tasks(fixture_tasks, "")) == ids(fixture_tasks)
    assert ids(tasks.filter_tasks(fixture_tasks, "P2-redact-ambiguous-prefix")) == ["P2-redact-ambiguous-prefix"]
    assert ids(tasks.filter_tasks(fixture_tasks, "P4")) == ["P4-fetch-no-allowlist"]
    assert ids(tasks.filter_tasks(fixture_tasks, "P4, P9-sha1-security-default")) == [
        "P4-fetch-no-allowlist", "P9-sha1-security-default"]
    assert tasks.filter_tasks(fixture_tasks, "P7") == []


def test_tasks_jsonl_round_trips(fixture_tasks):
    text = tasks.tasks_jsonl(fixture_tasks)
    lines = text.splitlines()
    assert len(lines) == 3 and text.endswith("\n")
    records = [json.loads(ln) for ln in lines]
    assert [Task(**r) for r in records] == fixture_tasks
    assert list(records[0]) == sorted(records[0])
    assert records[0]["canary"] == registry.canary()
    assert records[0]["source"] == "real-codebase"


# --------------------------------------------------------------------- the real catalogues

EXPECTED_COUNTS = {"research-replication-agent": 18, "smart-dispatch": 17,
                   "firstplay-backend": 11, "study-hub": 11}


def _all_checkouts_present(monkeypatch) -> bool:
    monkeypatch.delenv("SA_REPOS_ROOT", raising=False)
    if not (Path.home() / "Developer" / "projects" / "research-replication-agent" / ".git").exists():
        return False
    for cfg in repos.load_repos().values():
        src = repos.local_checkout(cfg)
        if src is None or not repos._has_commit(src, cfg.commit):
            return False
    return True


def test_load_all_tasks_real_catalogues(monkeypatch):
    """Read-only `git show` on the four local checkouts; skipped (never cloned) when any
    checkout or pinned commit is missing."""
    if not _all_checkouts_present(monkeypatch):
        pytest.skip("local project checkouts (or their pinned commits) are absent")
    out = tasks.load_all_tasks("all")
    assert {k: len(v) for k, v in out.items()} == EXPECTED_COUNTS
    for name, ts in out.items():
        assert len({t.task_id for t in ts}) == len(ts)
        for t in ts:
            assert t.file and t.find, (name, t.task_id)
            assert t.container_test[:3] == ["python", "-m", "pytest"], (name, t.task_id)
            assert t.eval_id == f"security.agent.{name}.v1"
            assert t.repo_path is not None
            assert t.canary == registry.canary()
    assert out["study-hub"][0].pythonpath == [".", "scripts"]
    assert out["research-replication-agent"][0].pythonpath == ["."]
