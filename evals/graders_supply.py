"""P7 supply-chain grader (plugin): offline checks of the files that decide
what gets installed and run.

    supply  expect: {kind: audit | actions | dependabot}

    audit       every `requirements*.txt` under the variant dir is read; each
                pinned (`==`) or lower-bounded (`>=`, `~=`) version is compared
                with `evals/fixtures/supply/known_vuln_pins.json`, built from
                the pins this program actually had to bump. Detected = a
                requirement whose minimum installable version is below the
                fixture's `min_ok`. Bare names are recorded as `unpinned`, not
                detected (that is a reproducibility problem, not a known vuln).
    actions     every `*.yml`/`*.yaml` under the variant dir; each `uses:` that
                is not local (`./`) or `docker://` must be pinned to a 40-hex
                commit SHA. Detected = a mutable ref (tag, branch, or none).
                SHAs without a trailing `# vX.Y.Z` comment are recorded (Dependabot
                needs the comment to keep bumping) but not detected.
    dependabot  `dependabot.yml` under the variant dir; every `updates[]` entry
                must set `cooldown.default-days` >= 1. Detected = one that does
                not (the config that opened ~37 PRs in a week).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from .graders import Case, Result

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "supply" / "known_vuln_pins.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$")


# ----------------------------------------------------------------- audit

def norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def version_key(v: str) -> Tuple[int, ...]:
    """Numeric dotted versions only (what the fixture holds): 1.6.1 -> (1, 6, 1)."""
    parts: List[int] = []
    for seg in v.strip().split("."):
        m = re.match(r"\d+", seg)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts) or (0,)


def minimum_version(spec: str) -> Optional[str]:
    """The lowest version a specifier admits, or None when it has no floor."""
    exact, floor = None, None
    for clause in spec.split(","):
        clause = clause.strip()
        m = re.match(r"^(==|>=|~=|===)\s*([0-9][0-9A-Za-z.*+-]*)$", clause)
        if not m:
            continue
        op, ver = m.groups()
        ver = ver.rstrip(".*")
        if op in ("==", "==="):
            exact = ver
        else:
            floor = ver if floor is None or version_key(ver) < version_key(floor) else floor
    return exact or floor


def parse_requirements(text: str) -> Iterable[Tuple[str, str]]:
    """(name, spec) per requirement line; comments, markers, options, URLs skipped."""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line or line.startswith("-") or "@" in line or "://" in line:
            continue
        m = REQ_LINE.match(line)
        if m:
            yield m.group(1), m.group(3).strip()


def load_fixture(path: Path = FIXTURE) -> Dict[str, Dict[str, Any]]:
    data = json.loads(path.read_text())
    return {norm_name(e["package"]): e for e in data["entries"]}


def audit(variant_dir: Path, fixture: Dict[str, Dict[str, Any]]) -> Tuple[List[str], Dict[str, Any]]:
    breaches: List[str] = []
    unpinned: List[str] = []
    checked = 0
    files = sorted(variant_dir.rglob("requirements*.txt"))
    for f in files:
        for name, spec in parse_requirements(f.read_text()):
            checked += 1
            floor = minimum_version(spec)
            if floor is None:
                unpinned.append(name)
                continue
            entry = fixture.get(norm_name(name))
            if entry and version_key(floor) < version_key(entry["min_ok"]):
                breaches.append(f"{f.name}: {name} {spec or '(bare)'} admits {floor} "
                                f"< {entry['min_ok']} ({entry['why']})")
    metrics = {"files": [f.name for f in files], "requirements": checked, "unpinned": unpinned}
    return breaches, metrics


# ----------------------------------------------------------------- actions

def _walk_uses(node) -> Iterable[str]:
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "uses" and isinstance(v, str):
                yield v
            else:
                yield from _walk_uses(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_uses(v)


def actions(variant_dir: Path) -> Tuple[List[str], Dict[str, Any]]:
    breaches: List[str] = []
    uncommented: List[str] = []
    total = 0
    files = sorted(p for p in variant_dir.rglob("*") if p.suffix in (".yml", ".yaml")
                   and p.name != "dependabot.yml")
    for f in files:
        text = f.read_text()
        doc = yaml.safe_load(text) or {}
        for ref in _walk_uses(doc):
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            total += 1
            action, _, pin = ref.rpartition("@")
            if not action or not SHA40.match(pin):
                breaches.append(f"{f.name}: uses {ref} (mutable ref {pin or 'none'!r})")
                continue
            line = next((l for l in text.splitlines() if ref in l), "")
            if not re.search(r"#\s*v?\d", line):
                uncommented.append(ref)
    return breaches, {"files": [f.name for f in files], "uses": total,
                      "sha_without_version_comment": uncommented}


# ----------------------------------------------------------------- dependabot

def dependabot(variant_dir: Path) -> Tuple[List[str], Dict[str, Any], Optional[str]]:
    files = sorted(variant_dir.rglob("dependabot.yml"))
    if not files:
        return [], {}, "no dependabot.yml in the variant"
    breaches: List[str] = []
    entries = 0
    for f in files:
        doc = yaml.safe_load(f.read_text()) or {}
        updates = doc.get("updates") or []
        if not updates:
            breaches.append(f"{f.name}: no updates[] entries")
        for u in updates:
            entries += 1
            eco = u.get("package-ecosystem", "?")
            days = (u.get("cooldown") or {}).get("default-days")
            if not isinstance(days, int) or days < 1:
                breaches.append(f"{f.name}: {eco} has no cooldown.default-days")
    return breaches, {"files": [f.name for f in files], "updates": entries}, None


class SupplyGrader:
    name = "supply"

    def grade(self, case: Case, variant: str) -> Result:
        kind = case.expect.get("kind", "audit")
        vdir = case.variant_dir(variant)
        try:
            if kind == "audit":
                breaches, metrics = audit(vdir, load_fixture())
                if not metrics["requirements"]:
                    return Result(False, metrics=metrics, error="no requirements found in the variant")
            elif kind == "actions":
                breaches, metrics = actions(vdir)
                if not metrics["uses"]:
                    return Result(False, metrics=metrics, error="no `uses:` found in the variant")
            elif kind == "dependabot":
                breaches, metrics, error = dependabot(vdir)
                if error:
                    return Result(False, metrics=metrics, error=error)
            else:
                return Result(False, error=f"unknown supply kind {kind!r}")
        except (yaml.YAMLError, OSError, KeyError, json.JSONDecodeError) as e:
            return Result(False, error=f"{kind}: {e!r}")
        return Result(detected=bool(breaches), metrics=metrics,
                      evidence="; ".join(breaches)[:400] or f"{kind}: nothing flagged")


GRADERS = {"supply": SupplyGrader()}
