"""Tests OF the P7 supply grader: known-bad pins, ranges, mutable action refs and
cooldown-less Dependabot configs are flagged; the fixed shapes are cleared; the
requirement/version parsing handles what real files contain."""
from pathlib import Path

import pytest

from evals.graders import Case, default_graders
from evals.graders_supply import (FIXTURE, SupplyGrader, load_fixture, minimum_version,
                                  parse_requirements, version_key)
from evals.run import REPO, discover, grade_case


def _case(tmp_path: Path, kind: str, files: dict) -> Case:
    """files = {"vuln": {relpath: text}, "clean": {relpath: text}}"""
    for variant, tree in files.items():
        for rel, text in tree.items():
            p = tmp_path / variant / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
    return Case(id="t", property="P7", origin="derived", grader="supply", path=tmp_path,
                expect={"kind": kind})


def test_fixture_is_well_formed_and_versions_compare():
    fx = load_fixture(FIXTURE)
    assert len(fx) >= 10 and all({"min_ok", "why"} <= set(e) for e in fx.values())
    assert version_key("1.6.1") > version_key("1.5.0") and version_key("1.10") > version_key("1.9")
    assert version_key("0.0.31") > version_key("0.0.20")
    assert version_key("2.0") < version_key("2.0.1") and version_key("3.1.3") > version_key("2.3.3")


def test_requirement_parsing_handles_real_lines():
    text = ("Flask==2.3.3  # comment\n"
            "security-agents[fetch] @ git+https://example.test/x@v0.1.1\n"
            "python-dotenv==1.2.1; python_version < \"3.10\"\n"
            "scikit-learn>=1.3.0,<1.7\n"
            "-r other.txt\n"
            "pyyaml\n")
    rows = dict(parse_requirements(text))
    assert rows == {"Flask": "==2.3.3", "python-dotenv": "==1.2.1",
                    "scikit-learn": ">=1.3.0,<1.7", "pyyaml": ""}
    assert minimum_version("==2.3.3") == "2.3.3"
    assert minimum_version(">=1.3.0,<1.7") == "1.3.0"
    assert minimum_version("<1.7") is None and minimum_version("") is None


def test_audit_flags_known_bad_pin_and_range_and_clears_fixed(tmp_path):
    c = _case(tmp_path, "audit", {
        "vuln": {"requirements.txt": "Flask-CORS==4.0.0\nrequests==2.32.3\n",
                 "requirements-dev.txt": "scikit-learn>=1.3.0\n"},
        "clean": {"requirements.txt": "Flask-CORS==6.0.5\nrequests==2.32.3\nscikit-learn==1.6.1\npyyaml\n"}})
    g = SupplyGrader()
    rv, rc = g.grade(c, "vuln"), g.grade(c, "clean")
    assert rv.detected and "Flask-CORS" in rv.evidence and "scikit-learn" in rv.evidence
    assert not rc.detected and rc.metrics["unpinned"] == ["pyyaml"]


def test_actions_flags_tags_and_branches_and_clears_shas(tmp_path):
    sha = "11d5960a326750d5838078e36cf38b85af677262"
    c = _case(tmp_path, "actions", {
        "vuln": {".github/workflows/ci.yml":
                 "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./local\n"
                 "  b:\n    uses: org/repo/.github/workflows/x.yml@main\n"},
        "clean": {".github/workflows/ci.yml":
                  f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{sha} # v4.4.0\n"
                  f"      - uses: docker://alpine:3.19\n      - uses: actions/setup-python@{sha}\n"}})
    g = SupplyGrader()
    rv, rc = g.grade(c, "vuln"), g.grade(c, "clean")
    assert rv.detected and rv.evidence.count("mutable ref") == 2
    assert not rc.detected and rc.metrics["sha_without_version_comment"] == [f"actions/setup-python@{sha}"]


def test_dependabot_flags_missing_cooldown_and_clears_the_template(tmp_path):
    bare = "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n    schedule: {interval: weekly}\n"
    with_cd = bare + "    cooldown:\n      default-days: 7\n"
    c = _case(tmp_path, "dependabot", {"vuln": {".github/dependabot.yml": bare},
                                       "clean": {".github/dependabot.yml": with_cd}})
    g = SupplyGrader()
    assert g.grade(c, "vuln").detected and not g.grade(c, "clean").detected
    template = (REPO / "templates" / "dependabot.yml").read_text()
    c2 = _case(tmp_path / "t", "dependabot", {"vuln": {}, "clean": {".github/dependabot.yml": template}})
    assert not g.grade(c2, "clean").detected
    assert g.grade(c2, "vuln").error              # no file: cannot be judged


@pytest.mark.parametrize("cid", [c.id for c in discover(REPO / "evals" / "cases") if c.property == "P7"])
def test_corpus_case_passes(cid):
    case = next(c for c in discover(REPO / "evals" / "cases") if c.id == cid)
    row = grade_case(case, default_graders(REPO))
    assert row["passed"], row
