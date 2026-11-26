# Fuzzing

Fuzzing proves a parser **degrades safely** on hostile input: it may reject, but
it must never crash with an undeclared exception, hang, or corrupt state. Any
function that reads untrusted bytes is a target — scraped HTML, downloaded PDF
text, a Canvas/Ed payload, an ERCOT feed row, a `.lvl` level string, a log line
on its way through `redact()`.

Two properties, four tools:

| Property | Tool | What it asks | Cost to run | When |
|---|---|---|---|---|
| Safe degradation | `fuzz_lib.assert_robust(parse, allowed)` (Hypothesis) | For any input, `parse` returns or raises a *declared* exception | seconds, no setup, runs in CI | **Every parser.** The first line; put it in `tests/security/`. |
| Cost (RC-2), whole parser | `fuzz_lib.size_sweep(parse)` | Runs of `" " "\n" "a" "(" "<" "{"` at 1k/10k/100k chars finish under a deadline and grow about linearly | ~0.1 s per parser, runs in CI | **Every parser that sees untrusted text.** Catches the quadratic loop, not just the quadratic regex. |
| Cost (RC-2), one regex | `secprim.bounded.redos_probe(pattern)` | A 10k-char adversarial run matches in under 100 ms | milliseconds | Every regex applied to untrusted text — a tighter bound than `size_sweep`, per pattern. |
| Safe degradation, deeper | `atheris_harness` / `run_atheris.sh` (Atheris + libFuzzer) | Same property as `assert_robust`, but the search is steered by bytecode coverage, with a per-input timeout | minutes to hours; clang/libFuzzer or Docker; opt-in | Parsers with **real branching in Python**: tokenizers, state machines, hand-written format readers. Not worth it for a wrapper around C-level `re` (see the numbers below). |

Hypothesis is the zero-setup, CI-friendly default and is what the per-project
`tests/security/test_fuzz_*.py` files use. The cost property is also a test:
`size_sweep` on a parser plus `redos_probe` on each of its regexes is the RC-2
"resource bounds" check for the text path, complementing `bounded_read` /
`safe_xml_fromstring` / `safe_zip_members` for bytes, XML and archives.

## 1. Property-based (Hypothesis) — the default

`assert_robust(parse, allowed=...)` returns a Hypothesis test; call it. The
`text_like` strategy mixes Hypothesis's search with a bank of nasty literals
(control bytes, delimiter soup, 100k-char inputs, partial UTF-8, injection-ish
markers). Anything raised outside `allowed` is a finding, shrunk to a minimal
input — e.g. `parse raised RecursionError on input '((((((...'`. Capture that
input as a regression case, fix the parser to reject it cleanly, re-run.

## 2. Cost property (`size_sweep`) — RC-2 for parsers

```python
from fuzzing.fuzz_lib import size_sweep
rows = size_sweep(parse)             # raises AssertionError on a blow-up; returns the table
```

Defaults: `sizes=(1_000, 10_000, 100_000)`, `units=(" ", "\n", "a", "(", "<", "{")`,
`deadline_s=0.5`, growth limit `size**1.4` between consecutive sizes (so 10x the
input may cost at most ~25x the time — an O(n²) parser costs ~100x and fails;
timer jitter around linear does not). Each timing is the best of three runs, and
steps whose smaller timing is under 1 ms are not ratioed (too fast to matter).

Worked example — `study-hub/scripts/redact.py` `redact()`, whose two header
regexes were quadratic on whitespace runs until 2026-11-25 (`redos_probe` found
the second one). The sweep over the fixed function, on an M-series laptop:

| unit | 1k | 10k | 100k | growth |
|---|---|---|---|---|
| `" "` | 0.10 ms | 1.00 ms | 9.8 ms | 10x / decade |
| `"\n"` | 0.11 ms | 1.08 ms | 10.9 ms | 10x |
| `"a"` | 0.04 ms | 0.39 ms | 3.9 ms | 10x |
| `"("` `"<"` `"{"` | 0.02 ms | 0.21 ms | 2.1 ms | 10x |

Linear, as fixed code should be. The pre-fix pattern would have shown ~100x per
decade on `" "` and tripped the 25x limit at 10k → 100k. `tests/test_fuzz_lib.py`
pins both sides with a linear toy and a deliberately quadratic one.

## 3. Coverage-guided (Atheris / libFuzzer) — the deeper track

`fuzzing/atheris_harness.py` is a generic harness for any `str -> Any` function:
it decodes libFuzzer's bytes as UTF-8 (replacement characters, never a decode
error), calls the target, swallows the declared exceptions, and lets anything
else escape so libFuzzer records the input. It sets `-timeout=5` per input
(libFuzzer's default is 1200 s), so a hang is a finding too. Findings land in
`fuzzing/crashes/<function>/` as `crash-*` / `timeout-*` / `oom-*` files.

```bash
# module:function must be importable from TARGET_SRC (default: cwd)
TARGET_SRC=../study-hub/scripts fuzzing/run_atheris.sh redact:redact 20000

# library form: only this function is instrumented
from fuzzing.atheris_harness import fuzz
fuzz(parse, (ValueError, KeyError), runs=20_000, seed_dir=Path("fuzzing/seeds/parse"))

# CLI form: the module is imported under instrument_imports(), so its imports are covered too
python -m fuzzing.atheris_harness redact:redact --runs 20000 --allowed ValueError,secprim.boundary.MalformedInput -- -len_control=0
```

### What actually ran here (2026-11-26, Apple Silicon macOS)

**Native install fails.** `pip install atheris` in a Python 3.12 venv dies in
the wheel build with

```
RuntimeError: Failed to find libFuzzer; you may be building using Apple Clang.
Apple Clang does not come with libFuzzer.
```

Apple's clang (21.0.0 here) ships no `libclang_rt.fuzzer_osx.a`, and no Homebrew
LLVM was installed. The fix Atheris suggests — build LLVM from source and set
`CLANG_BIN` — is hours of compile; the fallback below is minutes, so
`run_atheris.sh` uses it automatically whenever `python3 -c "import atheris"`
fails.

**Docker fallback works.** `fuzzing/Dockerfile.atheris` is `python:3.12-slim` +
`clang libclang-rt-dev` + `pip install atheris`. Two things it needs that are not
obvious: `libclang-rt-dev` (Debian splits libFuzzer out of `clang`), and
`CC=clang CXX=clang++ CLANG_BIN=/usr/bin/clang` — the slim image has no `cc`,
and without them Atheris's setup fails with "Unsupported compiler -- at least
C++11 support is needed!". With both, Atheris 3.0.0 builds from source in about
two minutes on linux/aarch64 (image 837 MB). The daemon on this machine is colima
(`colima start`), which shares only `$HOME` into the VM; `run_atheris.sh` warns
when `TARGET_SRC` is outside it, because the bind mount would come up empty.

| Run (`redact:redact`, 4 seed files) | Executions | Wall | Result |
|---|---|---|---|
| `run_atheris.sh redact:redact 20000` | 20,000 | < 1 s | no finding, `cov: 5 ft: 5` |
| `--runs 1000000 -- -len_control=0` | 1,000,000 | 5.4 s incl. container start (262,144 exec/s at the pulse) | no finding, `cov: 5` |
| `--runs 100000 --max-len 100000 -- -len_control=0` | 100,000 | 0.7 s | no finding |

`cov: 5` is the point to read: `redact()` is three Python lines around six
C-level `re.sub` calls, so bytecode coverage sees five edges and has nothing to
steer by — every input looks the same to libFuzzer, and the corpus collapses to
one byte. For regex-dominated code the right tools are `assert_robust`,
`size_sweep` and `redos_probe`; Atheris earns its setup on parsers with real
Python branching. The track is proven on one: a 15-line toy brace counter with
an undeclared `RecursionError` on depth > 3 was caught after **3,855
executions**, input `{\xb5}{{}{{\xb5x}{{` written to
`fuzzing/crashes/parse/crash-b9bf95a9…` (libFuzzer exit 77), with `cov: 8`
climbing as the fuzzer found the branches.

## Seed corpus convention

`fuzzing/seeds/<function>/` — one small file per realistic input shape, checked
in, **read-only**. The harness passes it to libFuzzer as a *second* corpus
directory; libFuzzer writes new coverage-increasing inputs only to the first,
which is `fuzzing/corpus/<function>/` (gitignored, persists between runs). The
first run of this harness got that wrong and libFuzzer rewrote `seeds/redact/`
into ten SHA-named one-liners — hence the split.

`fuzzing/seeds/redact/` is the example: a Playwright call log with cookie and
authorization headers, a JSON body with session/token fields, a JWT and a query
string, and a whitespace-and-openers line. Seed values are obvious placeholders
(`SEEDVALUEnotreal…`), never captured secrets. When a run finds a crash, fix the
bug, then copy the `crash-*` file into `seeds/<function>/` so the next run starts
from it and the regression is permanent.
