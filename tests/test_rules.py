"""Fixture tests for the custom Semgrep rules: each rule fires on a positive
snippet and stays silent on its negative. Skips if semgrep is not on PATH."""
import json
import os
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

RULES = Path(__file__).resolve().parents[1] / "semgrep" / "rules.yml"
SEMGREP = shutil.which("semgrep") or shutil.which(
    "semgrep", path=os.path.expanduser("~/Library/Python/3.9/bin"))
pytestmark = pytest.mark.skipif(SEMGREP is None, reason="semgrep not installed")

# rule id -> (positive snippet, negative snippet)
CASES = {
    "weak-hash-non-crypto": (
        'import hashlib\nk = hashlib.sha1(b"x").hexdigest()\n',
        'import hashlib\nk = hashlib.sha1(b"x", usedforsecurity=False).hexdigest()\n'
        'j = hashlib.sha256(b"x").hexdigest()\n',
    ),
    "torch-load-unsafe": (
        'import torch\nm = torch.load("m.pt")\n',
        'import torch\nm = torch.load("m.pt", weights_only=True)\n',
    ),
    "flask-dev-bind-all": (
        'app.run(host="0.0.0.0", port=5000)\n',
        'app.run(host="127.0.0.1", port=5000)\n',
    ),
    "subprocess-shell-true": (
        'import subprocess\nsubprocess.run(cmd, shell=True)\n',
        'import subprocess\nsubprocess.run(["ls", "-l"])\n',
    ),
    "yaml-unsafe-load": (
        'import yaml\nd = yaml.load(s)\n',
        'import yaml\nd = yaml.safe_load(s)\n',
    ),
    "requests-verify-disabled": (
        'import requests\nrequests.get(u, verify=False)\n',
        'import requests\nrequests.get(u)\n',
    ),
    "untrusted-text-into-prompt-sink": (
        'msgs = [{"role": "user", "content": f"Source:\\n{document_text}"}]\n',
        'msgs = [{"role": "user", "content": "Summarize the source below."}]\n',
    ),
    # LangChain bind site, firstplay's shape: the placeholder is bound by name
    # at invoke time, so the f-string rule above never sees it.
    "untrusted-placeholder-bound-unhardened": (
        'result = chain.invoke({"job_text": job_text})\n'
        'msgs = prompt.format_messages(resume_text=resume_text)\n'
        'r = invoke_with_retry(make_chain, {"job_text": job_text}, description="x")\n',
        'result = chain.invoke({"job_text": harden_untrusted(job_text)})\n'
        'result = chain.invoke({"job_text": security.harden_untrusted(job_text)})\n'
        'result = chain.invoke({"job_text": "Backend intern. Python, SQL."})\n'
        'result = chain.invoke({"format_instructions": parser.get_format_instructions()})\n'
        'msgs = prompt.format_messages(resume_text=harden(resume_text))\n'
        'logger.info("payload %s", {"text": job_text})\n'
        'result = chain.invoke(payload)\n',
    ),
    # The template half: a review aid pointing at the bind site.
    "untrusted-placeholder-in-prompt-template": (
        'prompt = ChatPromptTemplate.from_messages([\n'
        '    ("system", "You extract fields from a job posting."),\n'
        '    ("human", "Posting:\\n{job_text}"),\n'
        '])\n',
        'prompt = ChatPromptTemplate.from_messages([\n'
        '    ("system", "You extract fields from a job posting."),\n'
        '    ("human", "Return JSON matching {format_instructions}."),\n'
        '])\n'
        'other = ChatPromptTemplate.from_template("Answer in {language}.")\n',
    ),
}


def _findings(code: str, tmp_path: Path) -> set:
    tmp_path.mkdir(parents=True, exist_ok=True)
    f = tmp_path / "snippet.py"
    f.write_text(textwrap.dedent(code))
    # The `semgrep` binary execs `pysemgrep` from its own install dir, so that dir
    # must be on the child's PATH — not just resolvable by us.
    env = {**os.environ,
           "PATH": f"{Path(SEMGREP).parent}{os.pathsep}{os.environ.get('PATH', '')}"}
    out = subprocess.run(
        [SEMGREP, "scan", "--config", str(RULES), "--metrics", "off", "--quiet",
         "--json", str(f)], capture_output=True, text=True, timeout=120, env=env)
    # semgrep exits 0 (clean or findings without --error); anything else is a
    # tool failure and must fail the test loudly, never read as "no findings".
    if out.returncode != 0 or not out.stdout.strip():
        raise RuntimeError(f"semgrep failed (rc={out.returncode}):\n{out.stderr[-2000:]}")
    data = json.loads(out.stdout)
    return {r["check_id"].rsplit(".", 1)[-1] for r in data.get("results", [])}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_on_positive_and_not_on_negative(rule_id, tmp_path):
    pos, neg = CASES[rule_id]
    assert rule_id in _findings(pos, tmp_path / "pos"), f"{rule_id} did not fire"
    assert rule_id not in _findings(neg, tmp_path / "neg"), f"{rule_id} false positive"
