"""evals/agent/prompts.py: the two pre-registered prompt conditions, leakage stripping, and
the class-blind guarantee (no property, no description, no class word). Offline."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from evals.agent import prompts, runner
from evals.agent.prompts import CLASS_AWARE, CLASS_BLIND, Condition, agent_body, strip_leakage, system_body, user_text
from evals.agent.types import SCORE_NAMES, Task

REPO = Path(__file__).resolve().parents[1]
FORBIDDEN = ("P4", "egress", "SSRF", "fetch", "redirect", "safe_fetch", "CWE-918")
ADVISORY_DESCRIPTION = "an outbound request follows an attacker-controlled destination"


def _task(**over) -> Task:
    base = dict(task_id="P4-ghsa-aaaa-bbbb-cccc", eval_id="security.calib.egress.v1", repo="P4-ghsa-aaaa-bbbb-cccc",
                repo_url="https://example.invalid/x.git", commit="a" * 40, property="P4",
                description=ADVISORY_DESCRIPTION, file="pkg/client.py", find="", replace="",
                hidden_test="python -m pytest tests -q", suite_test="python -m pytest tests -q",
                container_test=["python", "-m", "pytest", "tests", "-q"], pythonpath=[],
                agent="agents/egress.md", canary="c", kind="advisory", source="advisory",
                fix_files=["pkg/client.py"], scope_rule="reachable-from-fix")
    base.update(over)
    return Task(**base)


def _mutation_task() -> Task:
    return _task(task_id="P4-arxiv-allowlist-dropped", repo="research-replication-agent", kind="mutation",
                 source="real-codebase", description="drop the host allow-list", find="a", replace="b",
                 fix_files=[], scope_rule="single-file")


def leaks(text: str) -> dict:
    """Whole-word, case-insensitive counts of the class words (governor's correction: the
    mandated instruction says "regression", whose substring is "egress"; W-B's build.py
    checks the same way)."""
    return {w: len(re.findall(r"(?<![A-Za-z0-9_])" + re.escape(w) + r"(?![A-Za-z0-9_])", text, re.I)) for w in FORBIDDEN}


def test_leaks_is_whole_word():
    assert leaks("add a regression test")["egress"] == 0
    assert leaks("the Egress path; SSRF-shaped; cwe-918; safe_fetch(); P4.")[("egress")] == 1
    assert leaks("the Egress path; SSRF-shaped; cwe-918; safe_fetch(); P4.") == {
        "P4": 1, "egress": 1, "SSRF": 1, "fetch": 0, "redirect": 0, "safe_fetch": 1, "CWE-918": 1}
    assert leaks("P40 prefetch")["P4"] == 0 and leaks("P40 prefetch")["fetch"] == 0


def _forbidden_hits(text: str) -> dict:
    return leaks(text)


# --------------------------------------------------------------------- Condition

def test_condition_names_and_requires():
    assert Condition().name == CLASS_AWARE and Condition().passed_requires == SCORE_NAMES
    blind = Condition(CLASS_BLIND)
    assert blind.name == "class-blind" and blind.verifier
    nov = Condition(CLASS_BLIND, verifier=False)
    assert nov.name == "class-blind+no_verifier"
    assert nov.passed_requires == ("recall", "fix", "scope_safety")
    with pytest.raises(ValueError):
        Condition("class-shy")


@pytest.mark.parametrize("name,mode,verifier", [
    ("class-blind", CLASS_BLIND, True), ("class-aware", CLASS_AWARE, True),
    ("class-blind+no_verifier", CLASS_BLIND, False), (" class-aware+no_verifier ", CLASS_AWARE, False),
])
def test_condition_parse(name, mode, verifier):
    c = Condition.parse(name)
    assert (c.mode, c.verifier) == (mode, verifier)
    assert Condition.parse(c.name) == c


@pytest.mark.parametrize("bad", ["", "blind", "class-blind+verifier", "class-aware-no_verifier", "P4"])
def test_condition_parse_rejects(bad):
    with pytest.raises(ValueError):
        Condition.parse(bad)


# --------------------------------------------------------------------- agent_body / strip_leakage

def test_agent_body_strips_front_matter_like_runner(tmp_path):
    p = tmp_path / "a.md"
    p.write_text("---\nname: x\nproperty: P4\n---\n\n# Agent\n\nbody\n")
    assert agent_body(p) == "# Agent\n\nbody\n"
    assert agent_body(p) == runner.agent_body(p)
    assert agent_body(REPO / "agents" / "egress.md").startswith("# Egress agent")


def test_strip_leakage_drops_miss_and_acceptance_sections():
    body = agent_body(REPO / "agents" / "egress.md")
    assert "## The miss" in body and "## Acceptance" in body and "evals/cases" in body
    stripped = strip_leakage(body)
    assert "The miss" not in stripped and "Acceptance" not in stripped and "evals/cases" not in stripped
    assert "smart-dispatch" not in stripped                      # the miss paragraph's body is gone too
    assert "## Goal" in stripped and "## Method" in stripped and "## Out of scope" in stripped
    assert "\n\n\n" not in stripped and stripped.endswith("\n")


def test_strip_leakage_section_boundaries_and_lines():
    body = ("# T\n\n## Goal\nkeep\n\n## Acceptance (how)\n`evals/agent/` runs `evals/cases/P4/*`\nmore\n\n"
            "## Keep me\nalso keep\nsee evals/cases/P1 for the corpus\n\n## The miss this agent exists to prevent\nx\n")
    out = strip_leakage(body)
    assert out == "# T\n\n## Goal\nkeep\n\n## Keep me\nalso keep\n"
    assert strip_leakage("") == "" and strip_leakage("plain\n") == "plain\n"


def test_every_shipped_spec_strips_clean():
    for spec in (REPO / "agents").glob("*.md"):
        if spec.name == "README.md":
            continue
        stripped = strip_leakage(agent_body(spec))
        assert "## The miss" not in stripped and "## Acceptance" not in stripped and "evals/cases" not in stripped, spec


# --------------------------------------------------------------------- class-blind guarantee

def test_class_blind_texts_contain_no_class_word():
    task = _task()
    cond = Condition.parse("class-blind")
    system = system_body(task, cond)
    user = user_text(task, cond, workdir="/app")
    assert system and user
    assert _forbidden_hits(system) == {w: 0 for w in FORBIDDEN}, _forbidden_hits(system)
    assert _forbidden_hits(user) == {w: 0 for w in FORBIDDEN}, _forbidden_hits(user)
    assert ADVISORY_DESCRIPTION not in user and task.task_id not in user and "Property:" not in user
    assert "/app" in user and "write_report" in user and "run_tests" in user and "oracle" in user.lower()
    # the substring check would also pass: our own texts avoid "regression" (substring "egress")
    for w in FORBIDDEN:
        assert w.lower() not in (system + user).lower(), w


def test_class_blind_system_is_generic_md_with_nine_categories():
    task = _task()
    system = system_body(task, Condition.parse("class-blind"))
    assert system.startswith("# Generic security agent")
    assert "Method" not in system.split("## Property categories")[0].replace("**Method:**", "")
    cats = [ln for ln in system.splitlines() if re.match(r"^[1-9]\. ", ln)]
    assert len(cats) == 9 and [int(c[0]) for c in cats] == list(range(1, 10))
    for word in ("safe_fetch", "CWE", "requests", "httpx", "urllib", "aiohttp", "Semgrep"):
        assert word.lower() not in system.lower(), word
    front = (REPO / "agents" / "generic.md").read_text().split("---")[1]
    assert "name: generic-security-agent" in front and "property: any" in front


def test_class_blind_ignores_task_agent_and_is_identical_across_tasks():
    cond = Condition.parse("class-blind")
    a = system_body(_task(), cond)
    b = system_body(_task(agent="agents/secrets.md", property="P5", task_id="P5-x", repo="P5-x"), cond)
    assert a == b
    assert user_text(_task(), cond, workdir="/app") == user_text(_task(property="P5", task_id="P5-x", repo="P5-x",
                                                                       description="other"), cond, workdir="/app")


# --------------------------------------------------------------------- class-aware

def test_class_aware_names_property_and_never_advisory_description():
    task = _task()
    cond = Condition.parse("class-aware")
    user = user_text(task, cond, workdir="/app")
    assert "Property: P4" in user and "property P4" in user and task.repo in user and "/app" in user
    assert ADVISORY_DESCRIPTION not in user and "Goal:" not in user
    system = system_body(task, cond)
    assert system.startswith("# Egress agent") and "The miss" not in system and "Acceptance" not in system


def test_class_aware_mutation_task_keeps_its_description():
    task = _mutation_task()
    user = user_text(task, Condition.parse("class-aware"), workdir="/work")
    assert "Goal: drop the host allow-list" in user and "Property: P4" in user and "/work" in user


def test_class_aware_uses_the_tasks_spec():
    task = _task(agent="agents/secrets.md", property="P5")
    assert system_body(task, Condition.parse("class-aware")).startswith("# Secrets agent")


# --------------------------------------------------------------------- hashes

def test_prompt_hashes_are_sha256_and_condition_specific():
    task = _task()
    h_blind = prompts.prompt_hashes(task, Condition.parse("class-blind"))
    h_aware = prompts.prompt_hashes(task, Condition.parse("class-aware"))
    assert set(h_blind) == {"system", "user"} and all(re.fullmatch(r"[0-9a-f]{64}", v) for v in h_blind.values())
    assert h_blind != h_aware
    assert h_blind == prompts.prompt_hashes(task, Condition.parse("class-blind+no_verifier"))   # same texts
    assert h_blind == prompts.prompt_hashes(task, Condition.parse("class-blind"), workdir="/app")
    assert h_blind["user"] != prompts.prompt_hashes(task, Condition.parse("class-blind"), workdir="/work")["user"]
