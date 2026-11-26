"""Tests OF the P5 secrets graders: a settings module that boots on a default
under a non-dev label is flagged, one that fails closed is cleared; a credential
file with group/other bits is flagged, a 0600 one is cleared."""
from pathlib import Path

import pytest

from evals.graders import Case, default_graders
from evals.graders_secrets import SecretsBootGrader, SecretsModeGrader
from evals.run import REPO, discover, grade_case

FAIL_OPEN = """
import os
API_KEY = os.environ.get("API_KEY") or ("dev-key" if os.environ.get("APP_ENV") != "production" else None)
if API_KEY is None: raise SystemExit(1)
"""
FAIL_CLOSED = """
from secprim import require_secret
API_KEY = require_secret("API_KEY", dev_default="dev-key")
"""
ALWAYS_RAISES = "raise RuntimeError('broken')\n"
NEVER_RAISES = "API_KEY = 'dev-key'\n"


def _boot_case(tmp_path: Path, vuln: str, clean: str) -> Case:
    for name, code in (("vuln", vuln), ("clean", clean)):
        (tmp_path / name).mkdir(parents=True)
        (tmp_path / name / "settings.py").write_text(code)
    return Case(id="t", property="P5", origin="derived", grader="secrets_boot", path=tmp_path,
                expect={"module": "settings", "secret": "API_KEY", "envs": ["staging", "prod "]})


def test_boot_grader_flags_fail_open_and_clears_fail_closed(tmp_path):
    c = _boot_case(tmp_path, FAIL_OPEN, FAIL_CLOSED)
    g = SecretsBootGrader()
    rv, rc = g.grade(c, "vuln"), g.grade(c, "clean")
    assert rv.detected and rv.metrics["booted_on_default"] == ["staging", "prod "]
    assert not rc.detected and rc.error is None


def test_boot_grader_errors_on_a_module_that_cannot_be_judged(tmp_path):
    c = _boot_case(tmp_path, ALWAYS_RAISES, NEVER_RAISES)
    g = SecretsBootGrader()
    assert "APP_ENV=dev" in g.grade(c, "vuln").error      # never boots: not clean, broken
    assert g.grade(c, "clean").detected                   # always boots: flagged


def test_boot_grader_never_leaks_the_secret_from_the_test_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("API_KEY", "leaked-from-the-runner")
    monkeypatch.setenv("APP_ENV", "dev")
    c = _boot_case(tmp_path, FAIL_OPEN, FAIL_CLOSED)
    assert not SecretsBootGrader().grade(c, "clean").detected


UMASK_WRITE = """
def write_session(path, data):
    open(path, "w").write(str(data))
"""
PRIVATE_WRITE = """
from secprim import write_private
def write_session(path, data):
    write_private(path, str(data))
"""


def _mode_case(tmp_path: Path, vuln: str, clean: str) -> Case:
    for name, code in (("vuln", vuln), ("clean", clean)):
        (tmp_path / name).mkdir(parents=True)
        (tmp_path / name / "s.py").write_text(code)
    return Case(id="t", property="P5", origin="derived", grader="secrets_mode", path=tmp_path,
                expect={"target": "s:write_session"})


def test_mode_grader_flags_umask_write_and_clears_write_private(tmp_path):
    c = _mode_case(tmp_path, UMASK_WRITE, PRIVATE_WRITE)
    g = SecretsModeGrader()
    rv, rc = g.grade(c, "vuln"), g.grade(c, "clean")
    assert rv.detected and rv.metrics["mode"] == "0o644"
    assert not rc.detected and rc.metrics["mode"] == "0o600"


def test_mode_grader_errors_when_nothing_is_written(tmp_path):
    c = _mode_case(tmp_path, "def write_session(path, data):\n    pass\n", PRIVATE_WRITE)
    assert "did not create" in SecretsModeGrader().grade(c, "vuln").error


@pytest.mark.parametrize("cid", [c.id for c in discover(REPO / "evals" / "cases")
                                 if c.property == "P5" and c.grader != "semgrep"])
def test_corpus_case_passes(cid):
    case = next(c for c in discover(REPO / "evals" / "cases") if c.id == cid)
    row = grade_case(case, default_graders(REPO))
    assert row["passed"], row
