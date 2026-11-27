"""SAST-tool output -> `agents/report.schema.json` report (Phase 1 amendment A4, W-D).

Every baseline is graded by the same recall criterion (a finding = a reported file and
line), so a static-analysis tool's native output is adapted to the report shape our
verifier reads. W-C's `SastAgent` resolves one of these by dotted path
(`--ak adapter=evals.calib.sast:semgrep_to_report`) after running the tool inside the box.

    sarif_to_report(sarif, tool=...)   SARIF 2.1.0 (CodeQL, and any tool with --sarif)
    semgrep_to_report(data)            `semgrep --json`: results[].check_id / path / start.line
    bandit_to_report(data)             `bandit -f json`: results[].test_id / filename / line_number
    pysa_to_report(data)               Pysa's `--output-format json` / taint-output.json: a list
                                       (or {"issues"/"results": [...]}) of {code, path, line, ...}

Pure functions: no I/O, no model, no tool invocation. Paths are made relative to the task
workdir (`/app/` and `./` prefixes stripped). `evidence` is the rule id and its categorical
message, never a sentence about exploitation; `claims` is always empty (a SAST tool makes
no verifiable claim); `property` is "P4" — the task class, since the adapter is used only
on this class's tasks (the rule ids themselves say what each tool looked for).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from . import PROPERTY, WORKDIR

_PREFIXES = (f"{WORKDIR}/", "./", "/")


def _rel(path: str) -> str:
    p = str(path or "")
    changed = True
    while changed:
        changed = False
        for pre in _PREFIXES:
            if p.startswith(pre):
                p = p[len(pre):]
                changed = True
    return p


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _report(tool: str, findings: List[Dict], *, repo: str, commit: str) -> Dict:
    return {"agent": tool, "property": PROPERTY, "repo": repo, "commit": commit,
            "findings": findings, "claims": []}


def _finding(fid: str, file: str, line: int, evidence: str, *, severity: Optional[str] = None) -> Dict:
    f: Dict[str, Any] = {"id": str(fid), "file": _rel(file), "line": int(line),
                         "evidence": " ".join(str(evidence).split())[:300], "status": "open"}
    if severity in ("high", "medium", "low"):
        f["severity"] = severity
    return f


def _dedupe(findings: Iterable[Dict]) -> List[Dict]:
    seen, out = set(), []
    for f in findings:
        key = (f["id"], f["file"], f["line"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


# ----------------------------------------------------------------- SARIF (CodeQL and others)

def sarif_to_report(sarif: Dict, *, tool: str, repo: str = WORKDIR, commit: str = "") -> Dict:
    """SARIF 2.1.0: runs[].results[].{ruleId, message.text, level, locations[].physicalLocation
    .{artifactLocation.uri, region.startLine}}. One finding per location."""
    findings: List[Dict] = []
    for run in sarif.get("runs") or []:
        for res in run.get("results") or []:
            rule = str(res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown-rule")
            msg = ((res.get("message") or {}).get("text") or "")
            level = str(res.get("level") or "")
            sev = {"error": "high", "warning": "medium", "note": "low"}.get(level)
            locs = res.get("locations") or []
            for loc in locs:
                phys = loc.get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri") or ""
                line = _int((phys.get("region") or {}).get("startLine"), 0)
                if not uri:
                    continue
                findings.append(_finding(rule, uri, line, f"{rule}: {msg}" if msg else rule, severity=sev))
    return _report(tool, _dedupe(findings), repo=repo, commit=commit)


# ----------------------------------------------------------------- semgrep

def semgrep_to_report(data: Dict, *, tool: str = "semgrep", repo: str = WORKDIR, commit: str = "") -> Dict:
    """`semgrep scan --json`: results[].{check_id, path, start.line, extra.{message, severity}}."""
    findings = []
    for r in data.get("results") or []:
        rule = str(r.get("check_id") or "unknown-rule")
        extra = r.get("extra") or {}
        sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get(str(extra.get("severity") or "").upper())
        msg = str(extra.get("message") or "")
        line = _int((r.get("start") or {}).get("line"), 0)
        findings.append(_finding(rule, str(r.get("path") or ""), line, f"{rule}: {msg}" if msg else rule, severity=sev))
    return _report(tool, _dedupe(findings), repo=repo, commit=commit)


# ----------------------------------------------------------------- bandit

def bandit_to_report(data: Dict, *, tool: str = "bandit", repo: str = WORKDIR, commit: str = "") -> Dict:
    """`bandit -f json`: results[].{test_id, test_name, filename, line_number, issue_severity, issue_text}."""
    findings = []
    for r in data.get("results") or []:
        rule = str(r.get("test_id") or "unknown-rule")
        name = str(r.get("test_name") or "")
        sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(str(r.get("issue_severity") or "").upper())
        line = _int(r.get("line_number"), 0)
        evidence = f"{rule}: {name}" if name else rule
        findings.append(_finding(rule, str(r.get("filename") or ""), line, evidence, severity=sev))
    return _report(tool, _dedupe(findings), repo=repo, commit=commit)


# ----------------------------------------------------------------- pysa

def pysa_to_report(data: Any, *, tool: str = "pysa", repo: str = WORKDIR, commit: str = "") -> Dict:
    """Pysa issues: a list (or {"issues": [...]} / {"results": [...]}) of
    {code, name, path, line, description}. `code` is the rule id."""
    if isinstance(data, dict):
        issues = data.get("issues") or data.get("results") or []
    else:
        issues = list(data or [])
    findings = []
    for r in issues:
        if not isinstance(r, dict):
            continue
        rule = str(r.get("code") if r.get("code") is not None else "unknown-rule")
        name = str(r.get("name") or "")
        line = _int(r.get("line"), 0)
        evidence = f"pysa-{rule}: {name}" if name else f"pysa-{rule}"
        findings.append(_finding(f"pysa-{rule}", str(r.get("path") or ""), line, evidence))
    return _report(tool, _dedupe(findings), repo=repo, commit=commit)


ADAPTERS = {"sarif": sarif_to_report, "semgrep": semgrep_to_report, "bandit": bandit_to_report, "pysa": pysa_to_report}
