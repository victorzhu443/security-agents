"""Graders: one interface, deterministic, wrapping the toolkit's own oracles.

    result = GRADERS[case.grader].grade(case, variant)   # variant: "vuln" | "clean"
    result.detected  -> the grader found the violation in that variant

A case's `expect` block tells the grader what to look for:

  semgrep    expect: {rule: <rule id suffix>}                 — rule must fire in vuln/, not in clean/
  fuzz       expect: {target: "mod:fn", allowed: [...], strategy: text|json, max_examples: N}
  cost       expect: {kind: regex|parser, target: "mod:attr", n: N, deadline_s: S}
  injection  expect: {target: "mod:fn"}                       — fn(untrusted_text) -> str

Targets are loaded from the variant directory, so vuln/ and clean/ ship the same
module name with different code.
"""
from __future__ import annotations

import builtins
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from hypothesis import strategies as st


@dataclass
class Result:
    detected: bool                      # violation present in this variant?
    metrics: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    error: Optional[str] = None          # grader could not run (tool missing, import failed)


@dataclass
class Case:
    id: str
    property: str                       # P1..P9, P0
    origin: str                         # historical-miss | derived
    grader: str
    expect: Dict[str, Any]
    path: Path                          # directory holding case.yaml, vuln/, clean/
    description: str = ""

    def variant_dir(self, variant: str) -> Path:
        return self.path / variant


# ----------------------------------------------------------------- helpers

def load_attr(variant_dir: Path, spec: str):
    """Import `mod:attr` from the variant directory under a unique module name."""
    mod_name, _, attr = spec.partition(":")
    if not attr:
        raise ValueError(f"target must be 'module:attr', got {spec!r}")
    path = variant_dir / (mod_name.replace(".", "/") + ".py")
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")
    uniq = f"evalcase_{abs(hash(str(path.resolve())))}_{mod_name}"
    sys.path.insert(0, str(variant_dir))
    try:
        spec_ = importlib.util.spec_from_file_location(uniq, path)
        mod = importlib.util.module_from_spec(spec_)
        spec_.loader.exec_module(mod)  # type: ignore[union-attr]
    finally:
        try:
            sys.path.remove(str(variant_dir))
        except ValueError:
            pass
    return getattr(mod, attr)


def resolve_exception(name: str):
    """'ValueError' -> ValueError; 'MalformedInput' / 'TooLarge' -> secprim's."""
    if hasattr(builtins, name):
        return getattr(builtins, name)
    import secprim
    if hasattr(secprim, name):
        return getattr(secprim, name)
    raise ValueError(f"unknown exception name {name!r}")


def json_like():
    """A structural strategy: nested dicts/lists with shapes a hostile payload
    would have (the keys a parser looks for, holding the wrong types)."""
    scalars = st.none() | st.booleans() | st.integers() | st.text(max_size=12)
    keys = st.sampled_from(["options", "label", "value", "name", "type", "id",
                            "controls", "fields", "items", "x"])
    return st.recursive(scalars,
                        lambda c: st.lists(c, max_size=4) | st.dictionaries(keys, c, max_size=4),
                        max_leaves=20)


# ----------------------------------------------------------------- graders

class SemgrepGrader:
    name = "semgrep"

    def __init__(self, rules: Path):
        self.rules = rules

    @staticmethod
    def _binary() -> Optional[str]:
        return shutil.which("semgrep") or shutil.which(
            "semgrep", path=os.path.expanduser("~/Library/Python/3.9/bin"))

    def grade(self, case: Case, variant: str) -> Result:
        binary = self._binary()
        if not binary:
            return Result(False, error="semgrep not installed")
        env = {**os.environ, "PATH": f"{Path(binary).parent}{os.pathsep}{os.environ.get('PATH', '')}"}
        out = subprocess.run(
            [binary, "scan", "--config", str(self.rules), "--metrics", "off", "--quiet",
             "--json", str(case.variant_dir(variant))],
            capture_output=True, text=True, timeout=300, env=env)
        if out.returncode != 0 or not out.stdout.strip():
            return Result(False, error=f"semgrep rc={out.returncode}: {out.stderr[-500:]}")
        fired = {r["check_id"].rsplit(".", 1)[-1] for r in json.loads(out.stdout).get("results", [])}
        want = case.expect["rule"]
        return Result(detected=want in fired, metrics={"rules_fired": sorted(fired)},
                      evidence=", ".join(sorted(fired)) or "no findings")


class FuzzGrader:
    """P1: the safe-degradation property. Detected = an undeclared exception."""
    name = "fuzz"

    def grade(self, case: Case, variant: str) -> Result:
        from fuzzing.fuzz_lib import assert_robust, text_like
        try:
            fn = load_attr(case.variant_dir(variant), case.expect["target"])
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        allowed = tuple(resolve_exception(n) for n in case.expect.get(
            "allowed", ["ValueError", "TypeError", "KeyError", "MalformedInput"]))
        strategy = json_like() if case.expect.get("strategy") == "json" else text_like
        try:
            assert_robust(fn, allowed=allowed, strategy=strategy,
                          max_examples=int(case.expect.get("max_examples", 200)))()
        except AssertionError as e:
            return Result(True, evidence=str(e)[:300])
        return Result(False, evidence="only declared exceptions")


class CostGrader:
    """P2: bounded cost. Detected = super-linear / over-deadline behaviour."""
    name = "cost"

    def grade(self, case: Case, variant: str) -> Result:
        from fuzzing.fuzz_lib import size_sweep
        from secprim.bounded import redos_probe
        try:
            target = load_attr(case.variant_dir(variant), case.expect["target"])
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        kind = case.expect.get("kind", "regex")
        try:
            if kind == "regex":
                pattern = re.compile(target) if isinstance(target, str) else target
                rows = redos_probe(pattern, n=int(case.expect.get("n", 10_000)),
                                   deadline_s=float(case.expect.get("deadline_s", 0.1)))
                worst = max(rows, key=lambda r: r[1])
                return Result(False, metrics={"worst_probe": worst[0], "worst_s": round(worst[1], 4)},
                              evidence=f"worst {worst[0]} {worst[1]*1000:.1f} ms")
            rows = size_sweep(target, deadline_s=float(case.expect.get("deadline_s", 0.5)))
            return Result(False, metrics={"rows": len(rows)}, evidence="linear")
        except AssertionError as e:
            return Result(True, evidence=str(e)[:300])


class InjectionGrader:
    """P8: LLM separation. Detected = any corpus attack lands (canary leaks)."""
    name = "injection"

    def grade(self, case: Case, variant: str) -> Result:
        from promptinject.corpus import corpus
        from promptinject.harness import evaluate
        try:
            fn = load_attr(case.variant_dir(variant), case.expect["target"])
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        report = evaluate(fn, corpus())
        attacks = [r for r in report.results if not r.is_control]
        landed = len(report.landed)
        control_fp = any(r.injected for r in report.results if r.is_control)
        asr = landed / len(attacks) if attacks else 0.0
        return Result(detected=landed > 0,
                      metrics={"asr": round(asr, 3), "landed": landed, "attacks": len(attacks),
                               "control_false_positive": control_fp},
                      evidence=f"{landed}/{len(attacks)} landed; control_fp={control_fp}")


def default_graders(repo_root: Path) -> Dict[str, Any]:
    return {
        "semgrep": SemgrepGrader(repo_root / "semgrep" / "rules.yml"),
        "fuzz": FuzzGrader(),
        "cost": CostGrader(),
        "injection": InjectionGrader(),
    }
