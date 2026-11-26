"""Generic Atheris (libFuzzer) harness for any `str -> Any` parser.

Coverage-guided fuzzing instruments the target's bytecode and mutates inputs
toward new branches, so it reaches states Hypothesis's random search does not.
The property it checks is the same one `fuzz_lib.assert_robust` checks: for any
input, the target returns or raises one of a *declared* set of exceptions. An
undeclared exception, a hang past `-timeout`, or a blow-up past `-rss_limit_mb`
is a finding; libFuzzer writes the input to `crash-*` / `timeout-*` / `oom-*`
under the artifact directory, and that file becomes a regression seed.

Library use (the target already imported; only that function is instrumented):

    from fuzzing.atheris_harness import fuzz
    fuzz(parse, (ValueError, KeyError), runs=20_000, seed_dir=Path("fuzzing/seeds/parse"))

Command line (the module is imported *under* instrumentation, so everything it
pulls in is covered too):

    python -m fuzzing.atheris_harness redact:redact --runs 20000

Atheris needs a clang with libFuzzer to build. Apple Clang has none, so on macOS
use `fuzzing/run_atheris.sh`, which runs this same module inside
`fuzzing/Dockerfile.atheris` when the host interpreter lacks `atheris`.
"""
from __future__ import annotations

import argparse
import builtins
import importlib
import os
import sys
from pathlib import Path
from typing import Any, Callable, Iterable, List, Optional, Sequence, Tuple

DEFAULT_ALLOWED: Tuple[type, ...] = (ValueError, KeyError, TypeError, UnicodeError, IndexError)

_HERE = Path(__file__).resolve().parent
SEEDS_ROOT = _HERE / "seeds"       # convention: fuzzing/seeds/<target>/ (checked in, read-only)
CORPUS_ROOT = _HERE / "corpus"     # libFuzzer's working corpus (gitignored)
CRASHES_ROOT = _HERE / "crashes"   # libFuzzer artifacts land here (gitignored)

_NO_ATHERIS = (
    "atheris is not importable in {exe}.\n"
    "It needs a clang that ships libFuzzer (Apple Clang does not). Either\n"
    "  * run fuzzing/run_atheris.sh, which falls back to fuzzing/Dockerfile.atheris, or\n"
    "  * pip install atheris in a Linux interpreter / a CLANG_BIN=<llvm clang> env."
)


def _atheris():
    try:
        import atheris  # type: ignore
    except ImportError as e:  # pragma: no cover — depends on the machine
        raise SystemExit(_NO_ATHERIS.format(exe=sys.executable)) from e
    return atheris


def make_one(target: Callable[[str], Any], allowed: Iterable[type]) -> Callable[[bytes], None]:
    """Build the per-input callback: bytes -> UTF-8 (replace) -> target.

    Declared exceptions are swallowed; everything else propagates so libFuzzer
    records the input. Pure Python, so it is unit-testable without Atheris."""
    allowed_t = tuple(allowed)

    def one(data: bytes) -> None:
        text = data.decode("utf-8", "replace")
        try:
            target(text)
        except allowed_t:
            return

    one.__name__ = f"fuzz_{getattr(target, '__name__', 'target')}"
    return one


def resolve_allowed(names: Iterable[str]) -> Tuple[type, ...]:
    """'ValueError,pkg.mod.Error' -> exception classes (builtins or dotted)."""
    out: List[type] = []
    for name in names:
        name = name.strip()
        if not name:
            continue
        if "." in name:
            mod, _, attr = name.rpartition(".")
            cls = getattr(importlib.import_module(mod), attr)
        else:
            cls = getattr(builtins, name, None)
        if not (isinstance(cls, type) and issubclass(cls, BaseException)):
            raise ValueError(f"{name!r} is not an exception class")
        out.append(cls)
    return tuple(out)


def load_target(spec: str) -> Callable[[str], Any]:
    """'module:function' (or 'module:Class.method') imported under instrumentation."""
    atheris = _atheris()
    mod_name, sep, attr = spec.partition(":")
    if not sep or not mod_name or not attr:
        raise SystemExit(f"target must be 'module:function', got {spec!r}")
    try:
        with atheris.instrument_imports():
            obj: Any = importlib.import_module(mod_name)
    except ModuleNotFoundError as e:
        if e.name != mod_name.split(".")[0]:
            raise
        raise SystemExit(
            f"cannot import {mod_name!r}; sys.path is {sys.path}.\n"
            "Natively: set PYTHONPATH (run_atheris.sh does this from TARGET_SRC).\n"
            "In Docker: TARGET_SRC is bind-mounted at /target — on macOS the VM "
            "(colima / Docker Desktop) shares only $HOME by default, so a path "
            "outside it mounts as an empty directory.") from e
    for part in attr.split("."):
        obj = getattr(obj, part)
    if not callable(obj):
        raise SystemExit(f"{spec} is not callable")
    return obj


def default_seed_dir(target: Callable) -> Optional[Path]:
    """fuzzing/seeds/<function name>/ if it exists, else None."""
    d = SEEDS_ROOT / getattr(target, "__name__", "")
    return d if d.is_dir() else None


def fuzz(
    target: Callable[[str], Any],
    allowed: Tuple[type, ...] = DEFAULT_ALLOWED,
    *,
    runs: int,
    seed_dir: Optional[Path] = None,
    artifact_dir: Optional[Path] = None,
    max_len: Optional[int] = None,
    timeout_s: int = 5,
    extra_args: Sequence[str] = (),
) -> None:
    """Fuzz `target` for `runs` executions; does not return on a finding.

    `seed_dir` holds the checked-in seeds and is read-only: libFuzzer writes
    coverage-increasing inputs only to the *first* corpus directory it is given,
    so the harness passes a working corpus under `fuzzing/corpus/<target>/`
    (gitignored, persists between runs) first and the seeds second. `timeout_s`
    is per input (libFuzzer's default is 1200 s, far too lax for a parser) —
    this is where the RC-2 cost property meets coverage guidance. Remaining
    libFuzzer flags go in `extra_args` (e.g. "-dict=...", "-len_control=0")."""
    atheris = _atheris()
    try:  # belt and braces: cover the target even if imported un-instrumented
        atheris.instrument_func(target)
    except Exception:  # noqa: BLE001 — builtins / C functions have no bytecode
        pass
    one = make_one(target, allowed)
    name = getattr(target, "__name__", "target")
    artifact_dir = artifact_dir or (CRASHES_ROOT / name)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir = CORPUS_ROOT / name
    corpus_dir.mkdir(parents=True, exist_ok=True)
    args = [
        sys.argv[0],
        f"-atheris_runs={int(runs)}",
        f"-timeout={int(timeout_s)}",
        f"-artifact_prefix={artifact_dir}{os.sep}",
        "-print_final_stats=1",
    ]
    if max_len:
        args.append(f"-max_len={int(max_len)}")
    args.extend(extra_args)
    args.append(str(corpus_dir))          # first dir: where libFuzzer writes
    if seed_dir is not None:
        args.append(str(seed_dir))        # later dirs: read-only seeds
    print(f"[atheris] target={name} runs={runs} allowed={[a.__name__ for a in allowed]} "
          f"seeds={seed_dir} corpus={corpus_dir} artifacts={artifact_dir}",
          file=sys.stderr, flush=True)
    atheris.Setup(args, one)
    atheris.Fuzz()


def main(argv: Optional[Sequence[str]] = None) -> None:
    ap = argparse.ArgumentParser(
        prog="python -m fuzzing.atheris_harness",
        description="Coverage-guided fuzz of a str -> Any function with Atheris.",
        epilog="Arguments after `--` are passed to libFuzzer unchanged.")
    ap.add_argument("target", help="module:function (importable via PYTHONPATH)")
    ap.add_argument("--runs", type=int, default=20_000, help="executions (default 20000)")
    ap.add_argument("--seeds", type=Path, default=None,
                    help="corpus dir (default fuzzing/seeds/<function>/ if present)")
    ap.add_argument("--allowed", default=",".join(c.__name__ for c in DEFAULT_ALLOWED),
                    help="comma-separated declared exceptions (builtins or dotted paths)")
    ap.add_argument("--artifacts", type=Path, default=None,
                    help="where crash-*/timeout-* inputs go (default fuzzing/crashes/<function>/)")
    ap.add_argument("--max-len", type=int, default=None, help="libFuzzer -max_len")
    ap.add_argument("--timeout", type=int, default=5, help="seconds per input (default 5)")
    argv = list(sys.argv[1:] if argv is None else argv)
    extra: List[str] = []
    if "--" in argv:
        i = argv.index("--")
        argv, extra = argv[:i], argv[i + 1:]
    ns = ap.parse_args(argv)
    target = load_target(ns.target)
    fuzz(target, resolve_allowed(ns.allowed.split(",")), runs=ns.runs,
         seed_dir=ns.seeds or default_seed_dir(target), artifact_dir=ns.artifacts,
         max_len=ns.max_len, timeout_s=ns.timeout, extra_args=extra)


if __name__ == "__main__":
    main()
