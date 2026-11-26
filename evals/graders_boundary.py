"""Plugin grader `refuse` — the refusal oracle for P1 (boundary) and P2 (bounded
cost). `fuzz` detects an *undeclared* exception and `cost` detects *time*; neither
expresses "this input must be turned away": a `float()` that accepts "nan", a
`root / relpath` that accepts "../x", a reader with no byte cap, an XML parser
that accepts an entity declaration. Those all *return normally*. This grader
feeds a fixed, hostile input set and requires a declared refusal for each.

  refuse   expect: {target: "mod:fn",
                    inputs: <named set> | [<value> | {kind: ..., ...}, ...],
                    accept: <named set> | [...],        # optional: must NOT be refused
                    refuse: [TooLarge],                 # exception names that count as a refusal
                    max_read: N}                        # optional: bytes a target may consume first

Named sets (literal values):
  nonfinite    nan / inf in every spelling a query parameter can carry
  finite_ok    ordinary numbers and numeric strings
  path_escape  absolute, `..`, drive, UNC, NUL, empty — what contained_path refuses
  path_ok      ordinary relative paths that stay inside the root

Constructed inputs ({kind: ..., size: N, ...}):
  zip_member   the PATH of a zip archive whose one member (`member`, default
               "data.bin") declares `size` bytes of `fill` (compressible, the
               default, or random); decompressed bytes are counted
  response     a fake HTTP response of `size` bytes with .read/.iter_bytes/
               .iter_content/.content/.text; bytes handed out are counted
  xml_dtd      bytes of an XML document carrying an internal entity declaration

A variant is DETECTED when any hostile input is not refused — the target returns,
raises something outside `refuse`, or (counted kinds) consumes more than
`max_read` bytes before refusing. An `accept` input that *is* refused is an
error, not a pass: a twin that refuses everything proves nothing.

Deterministic and offline: inputs are built in memory or in a temp dir, nothing
depends on the clock, and the stdlib `zipfile` patch used for counting is
restored in a `finally`.
"""
from __future__ import annotations

import os
import random
import shutil
import tempfile
import zipfile
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .graders import Case, Result, load_attr, resolve_exception

# ----------------------------------------------------------------- named sets

_NAMED: Dict[str, List[Any]] = {
    "nonfinite": ["nan", "NaN", " nan ", "inf", "-inf", "Infinity", "1e999", "-1e999",
                  float("nan"), float("inf"), float("-inf")],
    "finite_ok": ["25", "0", "3.5", "1e3", 10, 2.5],
    "path_escape": ["../outside.txt", "files/../../x", "a/b/../../../etc/x",
                    "/etc/cron.d/x", "\\abs", "C:x", "\\\\host\\share", "a\x00b", ""],
    "path_ok": ["files/notes.pdf", "ed/0001.md", "files/../a.txt"],
}


class _Counter:
    def __init__(self) -> None:
        self.bytes = 0


# ----------------------------------------------------------------- constructed inputs

class _CountingReader:
    """Wraps a zipfile.ZipExtFile so every decompressed byte is counted."""

    def __init__(self, inner, counter: _Counter) -> None:
        self._inner, self._counter = inner, counter

    def read(self, n: int = -1) -> bytes:
        b = self._inner.read(n)
        self._counter.bytes += len(b)
        return b

    def read1(self, n: int = -1) -> bytes:
        b = self._inner.read1(n)
        self._counter.bytes += len(b)
        return b

    def readline(self, limit: int = -1) -> bytes:
        b = self._inner.readline(limit)
        self._counter.bytes += len(b)
        return b

    def __iter__(self) -> Iterator[bytes]:
        for line in self._inner:
            self._counter.bytes += len(line)
            yield line

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self._inner.close()

    def __getattr__(self, name: str):
        return getattr(self._inner, name)


class _FakeResponse:
    """The slice of an HTTP response the toolkit's readers consume. Bytes are
    produced lazily from a repeating HTML block, so a 20 MB body costs nothing
    until the target actually reads it."""
    status_code = 200
    _BLOCK = (b"<p>" + b"a" * 60 + b"</p>\n") * 1000

    def __init__(self, size: int, counter: _Counter) -> None:
        self.size, self._pos, self._counter = int(size), 0, counter
        self.headers = {"content-type": "text/html; charset=utf-8",
                        "content-length": str(self.size)}

    def read(self, n: int = -1) -> bytes:
        remaining = self.size - self._pos
        if remaining <= 0:
            return b""
        want = remaining if n is None or n < 0 else min(n, remaining)
        out = bytearray()
        while len(out) < want:
            off = (self._pos + len(out)) % len(self._BLOCK)
            out += self._BLOCK[off:off + (want - len(out))]
        self._pos += want
        self._counter.bytes += want
        return bytes(out)

    def iter_bytes(self, chunk_size: int = 65536) -> Iterator[bytes]:
        while True:
            b = self.read(chunk_size)
            if not b:
                return
            yield b

    def iter_content(self, chunk_size: int = 65536) -> Iterator[bytes]:
        return self.iter_bytes(chunk_size)

    @property
    def content(self) -> bytes:
        return self.read()

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")


_XML_DTD = (b'<?xml version="1.0"?>\n'
            b'<!DOCTYPE sst [<!ENTITY e "expanded-entity-text">]>\n'
            b'<sst><si><t>&e;&e;&e;&e;</t></si></sst>')
_XML_PLAIN = b"<sst><si><t>hello</t></si><si><t>world</t></si></sst>"


def _make_zip(tmpdir: str, member: str, size: int, fill: str) -> str:
    """`fill: compressible` (default) is the bomb shape — a huge member in a tiny
    archive; `fill: random` is an ordinary ~1:1 member for `accept` inputs, so a
    ratio budget does not refuse the legitimate twin."""
    if fill == "random":
        data = random.Random(size).randbytes(int(size))      # seeded: the same bytes every run
    elif fill == "compressible":
        data = b"a" * int(size)
    else:
        raise ValueError(f"refuse: unknown zip fill {fill!r}")
    path = os.path.join(tmpdir, "input.zip")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(member, data)
    return path


def _build(spec: Any, tmpdir: str, counter: _Counter) -> Tuple[str, Any, Optional[Callable[[], None]]]:
    """-> (label, value, teardown). Dicts with a `kind` key are constructed inputs;
    anything else is a literal value handed to the target as-is."""
    if not (isinstance(spec, dict) and "kind" in spec):
        return repr(spec)[:60], spec, None
    kind = spec["kind"]
    size = int(spec.get("size", 1_000_000))
    if kind == "zip_member":
        member = str(spec.get("member", "data.bin"))
        path = _make_zip(tmpdir, member, size, str(spec.get("fill", "compressible")))
        orig_open = zipfile.ZipFile.open

        def counting_open(self, name, mode="r", pwd=None, *, force_zip64=False):
            f = orig_open(self, name, mode, pwd, force_zip64=force_zip64)
            return _CountingReader(f, counter) if mode == "r" else f

        zipfile.ZipFile.open = counting_open  # type: ignore[method-assign]

        def teardown() -> None:
            zipfile.ZipFile.open = orig_open  # type: ignore[method-assign]
        return f"zip_member {member} {size}B", path, teardown
    if kind == "response":
        return f"response {size}B", _FakeResponse(size, counter), None
    if kind == "xml_dtd":
        return "xml_dtd", _XML_DTD, None
    if kind == "xml_plain":
        return "xml_plain", _XML_PLAIN, None
    raise ValueError(f"refuse: unknown input kind {kind!r}")


def _expand(spec: Any) -> List[Any]:
    if spec is None:
        return []
    if isinstance(spec, str):
        if spec not in _NAMED:
            raise ValueError(f"refuse: unknown named set {spec!r} (have {sorted(_NAMED)})")
        return list(_NAMED[spec])
    if isinstance(spec, list):
        return list(spec)
    return [spec]


# ----------------------------------------------------------------- grader

class RefuseGrader:
    name = "refuse"

    def _call(self, fn, spec, refuse: tuple, tmpdir: str) -> Dict[str, Any]:
        counter = _Counter()
        label, value, teardown = _build(spec, tmpdir, counter)
        try:
            try:
                fn(value)
            except refuse as e:
                return {"label": label, "refused": True, "exc": type(e).__name__, "bytes": counter.bytes}
            except Exception as e:  # noqa: BLE001 — an undeclared type is not a refusal
                return {"label": label, "refused": False, "exc": type(e).__name__, "bytes": counter.bytes}
            return {"label": label, "refused": False, "exc": None, "bytes": counter.bytes}
        finally:
            if teardown:
                teardown()

    def grade(self, case: Case, variant: str) -> Result:
        try:
            fn = load_attr(case.variant_dir(variant), case.expect["target"])
            hostile = _expand(case.expect.get("inputs"))
            accept = _expand(case.expect.get("accept"))
            refuse = tuple(resolve_exception(n) for n in case.expect.get("refuse", ["TooLarge"]))
            max_read = case.expect.get("max_read")
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        if not hostile:
            return Result(False, error="refuse: expect.inputs is empty")

        tmpdir = tempfile.mkdtemp(prefix="evals-refuse-")
        try:
            for spec in accept:
                r = self._call(fn, spec, refuse, tmpdir)
                if r["refused"] or r["exc"]:
                    return Result(False, error=f"refuses legitimate input {r['label']}: {r['exc']}")
            rows = [self._call(fn, spec, refuse, tmpdir) for spec in hostile]
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        passed_through = [r for r in rows if not r["refused"]]
        over_read = [r for r in rows if max_read is not None and r["bytes"] > int(max_read)]
        evidence = []
        if passed_through:
            evidence.append("not refused: " + "; ".join(
                f"{r['label']}" + (f" ({r['exc']})" if r["exc"] else " (returned)") for r in passed_through))
        if over_read:
            evidence.append("read before refusing: " + "; ".join(
                f"{r['label']} consumed {r['bytes']}B (max_read {max_read})" for r in over_read))
        metrics = {"inputs": len(rows), "refused": len(rows) - len(passed_through),
                   "max_bytes_read": max((r["bytes"] for r in rows), default=0)}
        return Result(detected=bool(passed_through or over_read), metrics=metrics,
                      evidence="; ".join(evidence) or f"all {len(rows)} hostile inputs refused")


GRADERS = {"refuse": RefuseGrader()}
