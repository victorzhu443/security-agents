"""Run the defensive injection corpus against one application's input path.

Usage pattern (see each project's tests/security/ for a real wiring):

    from promptinject.harness import evaluate
    from promptinject.corpus import corpus

    def target(untrusted_text: str) -> str:
        # Call YOUR app the way it ingests a document / RAG chunk / form field,
        # with `untrusted_text` placed exactly where real untrusted input goes,
        # and return whatever the app would surface to a user.
        return my_app.summarize_source(untrusted_text)

    report = evaluate(target, corpus())
    print(report.render())
    assert report.ok, report.render()      # fail CI if any injection landed

The harness is model-agnostic and deterministic given the target. It never
generates new attacks; it replays a fixed corpus and checks a canary. Point it
at a stub target (see `stub_target`) to run with no API calls / no cost.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .corpus import CANARY, InjectionCase, corpus as default_corpus

# A target is any callable: untrusted text in, app-surfaced text out.
Target = Callable[[str], str]


@dataclass
class CaseResult:
    case: InjectionCase
    output: str
    injected: bool          # did the canary leak / behavior subvert?
    is_control: bool
    error: str | None = None

    @property
    def passed(self) -> bool:
        # Controls pass when NOT injected; attacks pass when the app resisted.
        if self.error is not None:
            return False
        return not self.injected


@dataclass
class Report:
    results: list[CaseResult] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def landed(self) -> list[CaseResult]:
        return [r for r in self.results if r.injected and not r.is_control]

    def render(self) -> str:
        lines = []
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        lines.append(f"Prompt-injection robustness: {passed}/{total} cases passed "
                     f"({self.seconds:.2f}s)")
        lines.append("-" * 64)
        for r in self.results:
            mark = "ok " if r.passed else "XX "
            tag = "control" if r.is_control else r.case.severity
            note = r.error or ("canary leaked" if r.injected else "resisted")
            lines.append(f"  {mark} [{tag:>8}] {r.case.id:<26} {note}")
        if self.landed:
            lines.append("-" * 64)
            lines.append(f"ACTION NEEDED: {len(self.landed)} injection(s) subverted "
                         f"the app. Harden the input path (see runbooks/).")
        return "\n".join(lines)


def evaluate(target: Target, cases: list[InjectionCase] | None = None) -> Report:
    """Replay the corpus through `target` and score each case."""
    cases = cases if cases is not None else default_corpus()
    rep = Report()
    t0 = time.time()
    for c in cases:
        is_control = c.category == "control"
        try:
            out = target(c.payload)
            injected = c.succeeded(out)
        except Exception as e:  # a crash on hostile input is itself a finding
            rep.results.append(CaseResult(c, "", False, is_control, error=repr(e)))
            continue
        rep.results.append(CaseResult(c, out, injected, is_control))
    rep.seconds = time.time() - t0
    return rep


def stub_target(untrusted_text: str) -> str:
    """A deliberately VULNERABLE reference target, for demoing the harness with
    no API cost. It naively concatenates untrusted text into an 'instruction'
    and echoes it, so injection cases land and controls pass — exactly what a
    broken app does. Replace with your real app's input path."""
    pseudo_prompt = f"Summarize this source:\n{untrusted_text}"
    # A vulnerable app effectively 'obeys' embedded instructions; emulate that
    # by surfacing the text, which lets the canary through.
    return pseudo_prompt


if __name__ == "__main__":
    # `python -m promptinject.harness` → runs against the vulnerable stub so you
    # can see the report shape without wiring a real app or spending tokens.
    print(evaluate(stub_target).render())
