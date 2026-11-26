# Fuzzing

Fuzzing proves a parser **degrades safely** on hostile input: it may reject, but
it must never crash with an undeclared exception, hang, or corrupt state. Any
function that reads untrusted bytes is a target — scraped HTML, downloaded PDF
text, a Canvas/Ed payload, an ERCOT feed row, a `.lvl` level string.

## Two tracks

**1. Property-based (Hypothesis) — the default here.** Zero native setup, runs in
CI, fast. `fuzz_lib.assert_robust(parse, allowed=...)` asserts the only property
that matters for safety: for any generated input, `parse` either returns or
raises one of a *declared* set of exceptions. Anything else is a finding. The
`text_like` strategy mixes Hypothesis's search with a bank of nasty literals
(control bytes, delimiter soup, 100k-char inputs, partial UTF-8, injection-ish
markers). See `tests/security/test_fuzz_*.py` inside each project.

**2. Coverage-guided (Atheris / libFuzzer) — the deeper track.** Instruments the
bytecode and mutates toward new coverage, finding bugs property testing misses.
It needs a clang toolchain and `pip install atheris`, which is why it is opt-in.
Template:

```python
import atheris, sys
with atheris.instrument_imports():
    from mymod import parse

def one(data: bytes):
    try:
        parse(data.decode("utf-8", "replace"))
    except (ValueError, KeyError, UnicodeError):
        pass  # declared failure modes

atheris.Setup(sys.argv, one)
atheris.Fuzz()
```

Run: `python fuzz_atheris.py -atheris_runs=200000`. A crash is written to a
`crash-*` file for a regression test.

## What a finding looks like

Hypothesis shrinks any failure to a minimal input and prints it, e.g.
`parse raised RecursionError on input '((((((...'`. Capture that input as a
regression case, fix the parser to reject it cleanly, re-run.
