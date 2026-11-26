"""Tests OF the P3 containment grader: it flags a runner that leaks the parent's
environment or cwd, clears one that contains both, treats the socket probe as
advisory, and restores its own process state. Then every P3 case passes."""
import os
import textwrap
from pathlib import Path

import pytest

from evals.graders import Case, default_graders
from evals.graders_containment import ENV_KEY, ContainmentGrader
from evals.run import REPO, discover, grade_case

CASES = REPO / "evals" / "cases"

LEAKY = """
import subprocess, sys
def run_untrusted(code, workdir):
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
"""
CONTAINED = """
import subprocess, sys
from secprim import child_env
def run_untrusted(code, workdir):
    return subprocess.run([sys.executable, "-c", code], cwd=workdir, env=child_env(),
                          capture_output=True, text=True, timeout=30)
"""


def _case(tmp_path: Path, vuln_src: str, clean_src: str, **expect) -> Case:
    for name, src in (("vuln", vuln_src), ("clean", clean_src)):
        (tmp_path / name).mkdir()
        (tmp_path / name / "runner.py").write_text(textwrap.dedent(src))
    return Case(id="t", property="P3", origin="derived", grader="containment",
                expect={"target": "runner:run_untrusted", **expect}, path=tmp_path)


def test_detects_env_and_cwd_leak_and_clears_contained_runner(tmp_path):
    g = ContainmentGrader()
    case = _case(tmp_path, LEAKY, CONTAINED)
    rv, rc = g.grade(case, "vuln"), g.grade(case, "clean")
    assert rv.error is None and rc.error is None, (rv, rc)
    assert rv.detected and rv.metrics["probes"]["env"] and rv.metrics["probes"]["cwd"]
    assert not rc.detected and not rc.metrics["probes"]["env"] and not rc.metrics["probes"]["cwd"]


def test_probe_selection_narrows_what_counts(tmp_path):
    g = ContainmentGrader()
    # leaks env but not cwd: counted only when env is in the probe list
    leaks_env_only = CONTAINED.replace("env=child_env(),", "")
    assert leaks_env_only != CONTAINED
    for sub, probes, want in (("a", ["cwd"], False), ("b", ["env"], True)):
        (tmp_path / sub).mkdir()
        assert g.grade(_case(tmp_path / sub, leaks_env_only, CONTAINED, probes=probes), "vuln").detected is want


def test_socket_probe_is_reported_but_advisory(tmp_path):
    r = ContainmentGrader().grade(_case(tmp_path, CONTAINED, CONTAINED), "clean")
    assert r.metrics["network_attempt_permitted"] is True   # loopback is reachable locally
    assert r.detected is False                                # ...and that is not counted


def test_unknown_probe_is_an_error_not_a_pass(tmp_path):
    r = ContainmentGrader().grade(_case(tmp_path, LEAKY, CONTAINED, probes=["memory"]), "vuln")
    assert r.error and "unknown probes" in r.error and r.detected is False


def test_grader_restores_its_own_env_and_cwd(tmp_path):
    before_cwd, before_env = os.getcwd(), os.environ.get(ENV_KEY)
    ContainmentGrader().grade(_case(tmp_path, LEAKY, CONTAINED), "vuln")
    assert os.getcwd() == before_cwd and os.environ.get(ENV_KEY) == before_env


def test_crashing_runner_is_an_error(tmp_path):
    r = ContainmentGrader().grade(_case(tmp_path, "def run_untrusted(code, workdir):\n    raise OSError('no')\n",
                                        CONTAINED), "vuln")
    assert r.error and "raised" in r.error


@pytest.mark.parametrize("cid", sorted(c.id for c in discover(CASES) if c.property == "P3"))
def test_p3_case_detects_vuln_and_clears_clean(cid):
    case = next(c for c in discover(CASES) if c.id == cid)
    row = grade_case(case, default_graders(REPO))
    if row["error"] and "not installed" in row["error"]:
        pytest.skip("semgrep not installed")
    assert row["error"] is None, row
    assert row["vuln"]["detected"] is True, row["vuln"]
    assert row["clean"]["detected"] is False, row["clean"]
    assert row["passed"]
