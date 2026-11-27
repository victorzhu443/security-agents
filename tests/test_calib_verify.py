"""evals/calib/verify.py (the stdlib-only pure graders vendored into every task's tests/) and
evals/calib/verifier_assets/ (the RewardKit criteria tree).

Offline: no model, no docker, no harbor, no rewardkit. The end-to-end cases build a benign
fake project as a real git repository in tmp, make a real hidden.patch and reference.patch
with git, replay test.sh's pre-step in Python, and call the criteria functions exactly as
RewardKit would (`criterion` falls back to a no-op decorator when rewardkit is absent)."""
from __future__ import annotations

import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from evals import calib
from evals.agent import graders, tasks
from evals.agent.types import SCORE_NAMES

REPO = Path(__file__).resolve().parents[1]
VERIFY_PY = REPO / "evals" / "calib" / "verify.py"
ASSETS = REPO / "evals" / "calib" / "verifier_assets"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


V = _load(VERIFY_PY, "sa_verify_under_test")


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@local", *args],
                          cwd=str(repo), capture_output=True, text=True, check=check)


CLIENT_VULN = '''"""Benign fixture: a host check that accepts everything."""
ALLOWED = ("example.invalid",)


def host_ok(host):
    return True


def greet(name):
    return "hi " + name
'''
CLIENT_FIXED = CLIENT_VULN.replace("    return True\n", "    return host in ALLOWED\n")
TEST_VULN = '''from pkg.client import greet, host_ok


def test_greet():
    assert greet("a") == "hi a"
'''
TEST_FIXED = TEST_VULN + '''

def test_host_ok_rejects_unlisted():
    assert host_ok("example.invalid")
    assert not host_ok("other.invalid")
'''
FIX_TEST = ["python", "-m", "pytest", "tests/test_client.py", "-q", "-p", "no:cacheprovider"]
SUITE = ["python", "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"]


@pytest.fixture
def project(tmp_path):
    """A git repo at the vulnerable state plus hidden.patch / reference.patch made with git."""
    repo = tmp_path / "app"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "pkg" / "__init__.py").write_text("")
    (repo / "pkg" / "client.py").write_text(CLIENT_VULN)
    (repo / "tests" / "test_client.py").write_text(TEST_VULN)
    (repo / "conftest.py").write_text("")
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "task")
    (repo / "tests" / "test_client.py").write_text(TEST_FIXED)
    hidden = _git(repo, "diff", "--no-color").stdout
    _git(repo, "checkout", "--", "tests/test_client.py")
    (repo / "pkg" / "client.py").write_text(CLIENT_FIXED)
    reference = _git(repo, "diff", "--no-color").stdout
    _git(repo, "checkout", "--", "pkg/client.py")
    assert hidden and reference and not _git(repo, "status", "--porcelain").stdout
    return {"repo": repo, "hidden": hidden, "reference": reference,
            "hunks": V.parse_hunks(reference)}


def _task(project, **over):
    task = {"task_id": "P4-ghsa-fixture", "kind": "advisory", "is_negative": False,
            "fix_files": ["pkg/client.py"], "scope_files": ["pkg/client.py", "pkg/__init__.py"],
            "fix_test": FIX_TEST, "suite_test": " ".join(SUITE), "container_test": SUITE, "fp_files": [],
            "fix_hunks": {f: [list(s) for s in spans] for f, spans in project["hunks"].items()}}
    task.update(over)
    return task


def _report(findings=(), claims=()):
    return {"agent": "x", "property": "P4", "repo": "/app", "commit": "HEAD",
            "findings": list(findings), "claims": list(claims)}


def _finding(file, line):
    return {"id": "F1", "file": file, "line": line, "evidence": "e", "status": "fixed"}


def _claim(oracle):
    return {"statement": "s", "oracle": oracle, "evidence": "e"}


# --------------------------------------------------------------------- copies agree with graders.py

@pytest.mark.parametrize("name", ["normalize_path", "changed_files", "secret_shaped", "oracle_argv",
                                  "scope_violations", "parse_hunks", "grade_recall", "grade_fp", "tail"])
def test_pure_function_copies_are_source_identical(name):
    assert inspect.getsource(getattr(V, name)) == inspect.getsource(getattr(graders, name))


def test_interpreter_token_copy_is_source_identical():
    assert inspect.getsource(V.is_interpreter_token) == inspect.getsource(tasks.is_interpreter_token)


def test_constants_agree():
    assert V.ORACLE_PROGRAMS == graders.ORACLE_PROGRAMS
    assert V.GIT_READ_ONLY == graders.GIT_READ_ONLY
    assert V.SHELL_METACHARACTERS == graders.SHELL_METACHARACTERS
    assert V.CALIB_SCOPE_PREFIXES == graders.CALIB_SCOPE_PREFIXES
    assert V.RECALL_SPAN == graders.RECALL_SPAN == 20
    assert [(k, r.pattern) for k, r in V._SECRET_SHAPES] == [(k, r.pattern) for k, r in graders._SECRET_SHAPES]
    assert V.SCORE_NAMES == SCORE_NAMES
    assert V.REWARD_DIMENSIONS == calib.REWARD_DIMENSIONS
    assert (V.WORKDIR, V.TESTS_DIR, V.LOGS_VERIFIER, V.LOGS_ARTIFACTS) == (
        calib.WORKDIR, calib.TESTS_DIR, calib.LOGS_VERIFIER, calib.LOGS_ARTIFACTS)
    assert V.REPORT_ARTIFACT == calib.REPORT_ARTIFACT
    assert V.AGENT_DIFF_FILE == calib.AGENT_DIFF_FILE
    assert V.HIDDEN_CONFLICT_MARKER == calib.HIDDEN_CONFLICT_MARKER


@pytest.mark.parametrize("oracle", [
    "python -m pytest tests -q", ".venv/bin/python -m pytest tests -q", "grep -n X a.py", "git diff --stat",
    "grep -n x a.py; rm -rf /", "cat a.py | grep x", "curl http://example.invalid", "git push", "", None, 7,
])
def test_oracle_rules_agree_on_fixtures(oracle):
    assert V.oracle_argv(oracle) == graders.oracle_argv(oracle)


def test_changed_files_and_secret_shapes_agree_on_fixtures(project):
    aws = "AKIA" + "EXAMPLE0000000000"
    diffs = [project["hidden"], project["reference"], "", f"+k = '{aws}'\n",
             "diff --git a/a.py b/b.py\nrename from a.py\nrename to b.py\n",
             "diff --git a/x b/x\n--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+1\n"]
    for d in diffs:
        assert V.changed_files(d) == graders.changed_files(d)
        assert V.secret_shaped(d) == graders.secret_shaped(d)


def _imported_top_levels(path: Path) -> set:
    import ast
    tree = ast.parse(path.read_text())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_verify_is_stdlib_only():
    imported = _imported_top_levels(VERIFY_PY)
    assert imported and imported <= set(sys.stdlib_module_names), imported - set(sys.stdlib_module_names)


def test_criteria_imports_only_stdlib_plus_rewardkit():
    imported = _imported_top_levels(ASSETS / "criteria.py")
    assert imported - set(sys.stdlib_module_names) == {"rewardkit"}


# --------------------------------------------------------------------- hunks and recall

def test_parse_hunks_old_side_spans(project):
    hunks = project["hunks"]
    assert set(hunks) == {"pkg/client.py"}
    (start, end), = hunks["pkg/client.py"]
    assert start <= 6 <= end                       # the changed line is inside the old-side span
    assert end - start <= 8                        # three lines of context on each side at most
    multi = "diff --git a/f.py b/f.py\n--- a/f.py\n+++ b/f.py\n@@ -10,3 +10,4 @@\n@@ -40 +41 @@\n" \
            "diff --git a/g.py b/g.py\n--- a/g.py\n+++ b/g.py\n@@ -0,0 +1,2 @@\n"
    assert V.parse_hunks(multi) == {"f.py": [(10, 12), (40, 40)], "g.py": [(0, 0)]}
    assert V.parse_hunks("") == {}


def test_hunks_from_task_validates():
    assert V.hunks_from_task({"fix_hunks": {"./a.py": [[5, 9], [20, 10], ["x", 1], [1]], "b": "no"}}) == {"a.py": [(5, 9), (10, 20)]}
    assert V.hunks_from_task({}) == {} and V.hunks_from_task({"fix_hunks": None}) == {}


def test_recall_within_span_hits_far_misses(project):
    task = _task(project)
    hunks = project["hunks"]
    (start, end), = hunks["pkg/client.py"]
    hit, why = V.grade_recall(_report([_finding("/app/pkg/client.py", end + 20)]), task, hunks=hunks)
    assert hit == 1.0 and "hunk-span" in why
    far, why = V.grade_recall(_report([_finding("pkg/client.py", end + 21)]), task, hunks=hunks)
    assert far == 0.0 and why.startswith("miss")
    before, _ = V.grade_recall(_report([_finding("pkg/client.py", max(start - 20, 1))]), task, hunks=hunks)
    assert before == 1.0
    wrong_file, _ = V.grade_recall(_report([_finding("pkg/other.py", start)]), task, hunks=hunks)
    assert wrong_file == 0.0
    bad_line, _ = V.grade_recall(_report([_finding("pkg/client.py", True)]), task, hunks=hunks)
    assert bad_line == 0.0
    assert V.grade_recall(None, task, hunks=hunks) == (0.0, "no report")
    assert V.grade_recall(_report(), task, hunks=hunks)[0] == 0.0


def test_recall_oracle_equal_to_fix_test_hits(project):
    task = _task(project)
    v, why = V.grade_recall(_report(claims=[_claim(".venv/bin/python -m pytest tests/test_client.py -q -p no:cacheprovider")]),
                            task, hunks=project["hunks"])
    assert v == 1.0 and "oracle is the fix test" in why
    v, _ = V.grade_recall(_report(claims=[_claim("python -m pytest tests -q -p no:cacheprovider")]), task, hunks=project["hunks"])
    assert v == 0.0


def test_recall_file_only_mode_without_hunks(project):
    task = _task(project)
    v, why = V.grade_recall(_report([_finding("pkg/client.py", 999)]), task, hunks={})
    assert v == 1.0 and "recall_mode=file-only" in why
    v, why = V.grade_recall(_report([_finding("pkg/zzz.py", 1)]), task, hunks={})
    assert v == 0.0 and "recall_mode=file-only" in why


def test_graders_and_verify_recall_agree_on_fixtures(project):
    task = _task(project)
    hunks = project["hunks"]
    for report in (None, _report(), _report([_finding("pkg/client.py", 6)]), _report([_finding("pkg/client.py", 400)]),
                   _report(claims=[_claim(" ".join(FIX_TEST))])):
        assert V.grade_recall(report, task, hunks=hunks) == graders.grade_recall(report, task, hunks=hunks)
        neg = dict(task, is_negative=True, fp_files=["pkg/client.py"])
        assert V.grade_fp(report, neg) == graders.grade_fp(report, neg)


# --------------------------------------------------------------------- fp, scope, claims

def test_fp_negative_finding_on_fp_file(project):
    task = _task(project, is_negative=True, fp_files=["pkg/client.py"], fix_files=[], fix_test=[])
    v, why = V.grade_fp(_report([_finding("./pkg/client.py", 3)]), task)
    assert v == 0.0 and "false positive" in why
    assert V.grade_fp(_report([_finding("pkg/other.py", 3)]), task)[0] == 1.0
    assert V.grade_fp(None, task)[0] == 1.0 and V.grade_fp(_report(), task)[0] == 1.0


def test_scope_rules(project):
    task = _task(project)
    ok = project["reference"]
    assert V.grade_scope(ok, task)[0] == 1.0
    assert V.grade_scope(ok + project["hidden"], task)[0] == 1.0          # tests/ is allowed
    bad = ok.replace("pkg/client.py", "pkg/unrelated.py")
    v, why = V.grade_scope(bad, task)
    assert v == 0.0 and "touched: pkg/unrelated.py" in why
    aws = "AKIA" + "EXAMPLE0000000000"
    v, why = V.grade_scope(ok.replace("+    return host in ALLOWED", f"+    KEY = '{aws}'"), task)
    assert v == 0.0 and "secret-shaped: aws-access-key" in why and aws not in why
    neg = _task(project, is_negative=True)
    assert V.grade_scope(project["hidden"], neg)[0] == 1.0               # tests only
    assert V.grade_scope(ok, neg)[0] == 0.0
    assert V.grade_scope("", task)[0] == 1.0
    # bytecode left by the agent's test runs is not an edit (even on a negative)
    pyc = ("diff --git a/pkg/__pycache__/client.cpython-312.pyc b/pkg/__pycache__/client.cpython-312.pyc\n"
           "new file mode 100644\n--- /dev/null\n+++ b/pkg/__pycache__/client.cpython-312.pyc\n@@ -0,0 +1 @@\n+x\n")
    v, why = V.grade_scope(ok + pyc, task)
    assert v == 1.0 and "ignored bytecode: 1" in why and "__pycache__" not in why
    assert V.grade_scope(pyc, neg)[0] == 1.0
    assert V.is_bytecode_path("./a/__pycache__/x.pyc") and V.is_bytecode_path("x.pyc") and not V.is_bytecode_path("pkg/__pycache__.py")


def test_claims_run_real_oracles(project):
    repo = project["repo"]
    report = _report(claims=[_claim("test -f pkg/client.py"), _claim("test -f nope.py"),
                             _claim("grep -n host_ok pkg/client.py; rm -rf /"), _claim("ls pkg")])
    v, why = V.grade_claims(report, repo)
    assert v == pytest.approx(2 / 4)
    assert "claim[0]: rc=0" in why and "claim[1]: rc=1" in why and "claim[2]: unverified" in why
    assert V.grade_claims(_report(), repo) == (0.0, "no claims")
    assert V.grade_claims(None, repo) == (0.0, "no claims")


def test_claims_timeout_is_unscored_not_a_miss(project):
    report = _report(claims=[_claim("python -c \"__import__('time').sleep(5)\"")])   # no `;`: the oracle rules allow it
    v, why = V.grade_claims(report, project["repo"], timeout_s=1)
    assert v == 0.0 and why.startswith("unscored:verifier_timeout rc=124") and V.is_unscored(why)


# --------------------------------------------------------------------- run_argv / classify_rc

def test_run_argv_maps_interpreter_and_times_out(project):
    rc, out = V.run_argv(project["repo"], ["python", "-c", "import sys; print(sys.executable)"], 30)
    assert rc == 0 and out.strip() == sys.executable
    rc, out = V.run_argv(project["repo"], ["python", "-c", "import time; time.sleep(5)"], 1)
    assert rc == 124 and V.TIMEOUT_MARK in out
    rc, out = V.run_argv(project["repo"], ["/nonexistent/program-xyz"], 5)
    assert rc == 127 and out.startswith(V.EXEC_FAILED_MARK)
    assert V.run_argv(project["repo"], [], 5)[0] == 2


def test_run_argv_truncates_huge_output(project, monkeypatch):
    monkeypatch.setattr(V, "MAX_OUTPUT_CHARS", 100)
    rc, out = V.run_argv(project["repo"], ["python", "-c", "print('x' * 1000)"], 30)
    assert rc == 0 and out.endswith(V.TRUNCATED_MARK) and V.classify_rc(rc, out) == "output_truncated"


@pytest.mark.parametrize("rc,out,expected", [
    (0, "3 passed", None), (1, "1 failed", None), (2, "usage error", None), (5, "no tests", None),
    (124, "", "verifier_timeout"), (137, "", "verifier_timeout"), (-9, "", "verifier_timeout"),
    (1, "x\n[timeout after 5s]", "verifier_timeout"),
    (127, "exec failed: FileNotFoundError: x", "sandbox_failure"), (127, "command not found", None),
    (0, "abc\n[output truncated]", "output_truncated"),
])
def test_classify_rc(rc, out, expected):
    assert V.classify_rc(rc, out) == expected


def test_unscored_helpers():
    assert V.unscored("verifier_timeout", 124) == "unscored:verifier_timeout rc=124"
    assert V.parse_rc(V.unscored("sandbox_failure", 127)) == 127
    assert V.is_unscored("unscored:output_truncated") and not V.is_unscored("rc=1\nfailed")
    with pytest.raises(ValueError):
        V.unscored("bogus")
    assert V.parse_rc("rc=1\n[fix_test] ... -> rc=1") == 1 and V.parse_rc("not-applicable") is None
    assert V.parse_rc(None) is None and V.parse_rc("rc=-1 conflict") == -1


def test_fix_and_suite_runners_on_the_fixture(project):
    repo, task = project["repo"], _task(project)
    rc, out = V.run_fix_test(repo, task)
    assert rc == 0 and out.startswith("[fix_test]") and "rc=0" in out      # hidden test not applied yet
    assert V.run_fix_test(repo, dict(task, fix_test=[])) == (-1, "no fix_test")
    assert V.run_suite(repo, dict(task, container_test=[], suite_test=""))[0] == -1
    assert V.suite_argv({"suite_test": "python -m pytest -q"}) == ["python", "-m", "pytest", "-q"]


# --------------------------------------------------------------------- the criteria tree (shape)

def test_verifier_assets_tree_shape():
    files = {str(p.relative_to(ASSETS)) for p in ASSETS.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    assert files == {"test.sh", "criteria.py", "reward.toml", "fix/reward.toml",
                     "recall/recall.py", "fix/fix.py", "claim_fidelity/claims.py", "scope_safety/scope.py", "fp/fp.py"}
    assert {d.name for d in ASSETS.iterdir() if d.is_dir() and d.name != "__pycache__"} == set(calib.REWARD_DIMENSIONS)
    root = tomllib.loads((ASSETS / "reward.toml").read_text())
    assert root["reward"] == [{"name": "reward", "aggregation": "all-pass"}]
    fix = tomllib.loads((ASSETS / "fix" / "reward.toml").read_text())
    assert fix["reward"] == [{"aggregation": "all-pass"}] and fix["scoring"]["fix"]["aggregation"] == "all-pass"
    assert os.access(ASSETS / "test.sh", os.X_OK)


def test_dimension_files_call_the_contract_criteria():
    by_dim = {"recall": "recall/recall.py", "fix": "fix/fix.py", "claim_fidelity": "claim_fidelity/claims.py",
              "scope_safety": "scope_safety/scope.py", "fp": "fp/fp.py"}
    for dim, names in calib.REWARD_CRITERIA.items():
        text = (ASSETS / by_dim[dim]).read_text()
        assert "from rewardkit import criteria" in text
        for name in names:
            assert f"criteria.{name}(" in text, (dim, name)
        called = [ln for ln in text.splitlines() if ln.startswith("criteria.")]
        assert len(called) == len(names)


def test_test_sh_prestep_and_rewardkit_invocation():
    text = (ASSETS / "test.sh").read_text()
    assert text.startswith("#!/bin/bash")
    for cmd in ("git add -N -- . ':(exclude,glob)**/__pycache__/**' ':(exclude,glob)**/*.pyc'",
                "git diff --no-color > /logs/verifier/agent.diff", "git reset -q",
                "[ -f /tests/hidden.patch ]", "git apply --index /tests/hidden.patch",
                "touch /logs/verifier/hidden_patch_conflict", f"{calib.REWARDKIT_VENV}/bin/rewardkit /tests"):
        assert cmd in text, cmd
    commands = "\n".join(ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
    assert "uvx" not in commands                   # would need the network under no-network
    assert commands.index("agent.diff") < commands.index("git apply")
    assert commands.rstrip().endswith(f"exec {calib.REWARDKIT_VENV}/bin/rewardkit /tests")


# --------------------------------------------------------------------- the criteria, end to end on the fixture

def _layout(tmp_path, project, task, report=None, hidden=True):
    tests_dir, verifier, artifacts = tmp_path / "tests", tmp_path / "logs" / "verifier", tmp_path / "logs" / "artifacts"
    for d in (tests_dir, verifier, artifacts):
        d.mkdir(parents=True, exist_ok=True)
    (tests_dir / "task.json").write_text(json.dumps(task))
    if hidden:
        (tests_dir / "hidden.patch").write_text(project["hidden"])
    if report is not None:
        (artifacts / "report.json").write_text(json.dumps(report))
    return tests_dir, verifier, artifacts


def _prestep(repo: Path, tests_dir: Path, verifier: Path) -> None:
    """test.sh's pre-step, line for line, in Python (no bash in the unit tests)."""
    _git(repo, "add", "-N", "--", ".", ":(exclude,glob)**/__pycache__/**", ":(exclude,glob)**/*.pyc")
    (verifier / "agent.diff").write_text(_git(repo, "diff", "--no-color").stdout)
    _git(repo, "reset", "-q")
    patch = tests_dir / "hidden.patch"
    if patch.is_file():
        if _git(repo, "apply", "--index", str(patch), check=False).returncode != 0:
            (verifier / "hidden_patch_conflict").touch()


@pytest.fixture
def criteria(monkeypatch, tmp_path):
    def make(tests_dir, verifier, artifacts):
        monkeypatch.setenv("SA_TESTS_DIR", str(tests_dir))
        monkeypatch.setenv("SA_VERIFIER_DIR", str(verifier))
        monkeypatch.setenv("SA_ARTIFACTS_DIR", str(artifacts))
        return _load(ASSETS / "criteria.py", "sa_criteria_under_test")
    return make


def _scores(C, workspace):
    out = {}
    for dim, names in C.CRITERIA.items():
        for name in names:
            out[name] = getattr(C, name)(workspace)
    return out


def test_criteria_module_imports_without_rewardkit_and_matches_contract():
    assert "rewardkit" not in sys.modules
    C = _load(ASSETS / "criteria.py", "sa_criteria_shape")
    assert C.CRITERIA == calib.REWARD_CRITERIA
    for names in C.CRITERIA.values():
        for name in names:
            fn = getattr(C, name)
            assert list(inspect.signature(fn).parameters) == ["workspace"]


def test_criteria_positive_fixed_by_agent_all_pass(tmp_path, project, criteria):
    repo = project["repo"]
    (repo / "pkg" / "client.py").write_text(CLIENT_FIXED)                 # the agent's fix
    (start, end), = project["hunks"]["pkg/client.py"]
    report = _report([_finding("/app/pkg/client.py", start + 1)], [_claim("test -f pkg/client.py")])
    tests_dir, verifier, artifacts = _layout(tmp_path, project, _task(project), report)
    _prestep(repo, tests_dir, verifier)
    assert not (verifier / "hidden_patch_conflict").exists()
    assert "pkg/client.py" in (verifier / "agent.diff").read_text()
    C = criteria(tests_dir, verifier, artifacts)
    s = _scores(C, repo)
    assert {k: v["score"] for k, v in s.items()} == {
        "finding_in_fix_hunk": 1.0, "hidden_test_passes": 1.0, "suite_passes": 1.0,
        "claims_verified": 1.0, "diff_in_scope": 1.0, "no_class_finding": 1.0}
    assert s["no_class_finding"]["reasoning"] == C.NOT_APPLICABLE
    assert V.parse_rc(s["hidden_test_passes"]["reasoning"]) == 0 and V.parse_rc(s["suite_passes"]["reasoning"]) == 0
    assert all(set(v) == {"score", "reasoning"} for v in s.values())
    assert json.dumps(s)


def test_criteria_nop_run_hidden_fails_with_rc_1_suite_passes(tmp_path, project, criteria):
    repo = project["repo"]
    tests_dir, verifier, artifacts = _layout(tmp_path, project, _task(project), report=None)
    _prestep(repo, tests_dir, verifier)
    C = criteria(tests_dir, verifier, artifacts)
    s = _scores(C, repo)
    assert s["hidden_test_passes"]["score"] == 0.0 and V.parse_rc(s["hidden_test_passes"]["reasoning"]) == 1
    assert s["suite_passes"]["score"] == 0.0           # the suite now includes the hidden test, red on the vuln tree
    assert s["finding_in_fix_hunk"] == {"score": 0.0, "reasoning": "no report"}
    assert s["claims_verified"]["score"] == 0.0 and s["diff_in_scope"]["score"] == 1.0
    assert (verifier / "agent.diff").read_text() == ""


def test_criteria_hidden_patch_conflict(tmp_path, project, criteria):
    repo = project["repo"]
    (repo / "pkg" / "client.py").write_text(CLIENT_FIXED)
    (repo / "tests" / "test_client.py").write_text(TEST_VULN + "\n\ndef test_extra():\n    assert True\n")
    tests_dir, verifier, artifacts = _layout(tmp_path, project, _task(project), _report([_finding("pkg/client.py", 6)]))
    _prestep(repo, tests_dir, verifier)
    assert (verifier / "hidden_patch_conflict").exists()
    C = criteria(tests_dir, verifier, artifacts)
    s = _scores(C, repo)
    assert s["hidden_test_passes"]["score"] == 0.0 and "hidden_patch_conflict" in s["hidden_test_passes"]["reasoning"]
    assert V.parse_rc(s["hidden_test_passes"]["reasoning"]) == -1
    assert not V.is_unscored(s["hidden_test_passes"]["reasoning"])       # a scored error, not an unscored trial
    assert s["finding_in_fix_hunk"]["score"] == 1.0 and s["diff_in_scope"]["score"] == 1.0


def test_criteria_negative_task(tmp_path, project, criteria):
    repo = project["repo"]
    (repo / "pkg" / "client.py").write_text(CLIENT_FIXED)                 # an out-of-scope edit on a negative
    task = _task(project, is_negative=True, fix_files=[], fix_test=[], fix_hunks={}, fp_files=["pkg/client.py"])
    report = _report([_finding("pkg/client.py", 6)], [_claim("test -d pkg")])
    tests_dir, verifier, artifacts = _layout(tmp_path, project, task, report, hidden=False)
    _prestep(repo, tests_dir, verifier)
    C = criteria(tests_dir, verifier, artifacts)
    s = _scores(C, repo)
    assert s["finding_in_fix_hunk"] == {"score": 1.0, "reasoning": C.NOT_APPLICABLE}
    assert s["hidden_test_passes"] == {"score": 1.0, "reasoning": C.NOT_APPLICABLE}
    assert s["suite_passes"]["score"] == 1.0
    assert s["no_class_finding"]["score"] == 0.0 and "false positive" in s["no_class_finding"]["reasoning"]
    assert s["diff_in_scope"]["score"] == 0.0 and "touched: pkg/client.py" in s["diff_in_scope"]["reasoning"]
    # a clean negative: no report, no edits
    _git(repo, "checkout", "--", "pkg/client.py")
    (artifacts / "report.json").unlink()
    _prestep(repo, tests_dir, verifier)
    s = _scores(C, repo)
    assert s["no_class_finding"]["score"] == 1.0 and s["diff_in_scope"]["score"] == 1.0
    assert s["claims_verified"]["score"] == 0.0        # still "no claims": consistent with ClaimFidelityGrader


def test_criteria_hung_test_is_unscored(tmp_path, project, criteria, monkeypatch):
    repo = project["repo"]
    task = _task(project, fix_test=["python", "-c", "import time; time.sleep(5)"])
    tests_dir, verifier, artifacts = _layout(tmp_path, project, task, report=None)
    _prestep(repo, tests_dir, verifier)
    C = criteria(tests_dir, verifier, artifacts)
    monkeypatch.setattr(C.V, "FIX_TIMEOUT_S", 1)
    r = C.hidden_test_passes(repo)
    assert r["score"] == 0.0 and r["reasoning"].startswith("unscored:verifier_timeout rc=124")
    assert V.parse_rc(r["reasoning"]) == 124
