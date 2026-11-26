"""P3 containment grader (plugin; discovered by evals.graders.default_graders).

A case exposes `run_untrusted(code: str, workdir: Path)` (or whatever `expect.target`
names) returning anything with `.stdout` (str) and `.returncode` — normally a
`subprocess.CompletedProcess`. The grader plants a canary in its OWN process (an
environment variable, and a working directory that is not `workdir`), then runs three
tiny, benign probe programs through the case's function:

  env      print one environment variable          -> leaked   if the canary is in stdout
  cwd      write a marker file in the process cwd   -> escaped  if it lands outside workdir
  socket   connect to 127.0.0.1 on a closed port    -> permitted if the attempt reached the stack

    expect: {target: "runner:run_untrusted", probes: [env, cwd]}

Detected = any probe named in `expect.probes` succeeded (default: env and cwd). The
socket probe always runs and is reported in `metrics`, but counts only when listed:
loopback stays reachable even under `docker run --network none`, so no local runner
can make it fail; it is a hook for a backend that drops network namespaces entirely.
Memory and pids probes are omitted on purpose: RLIMIT_AS / RLIMIT_NPROC are advisory on
macOS, so a local grader could not tell a cap from its absence.

The probes are deliberately trivial. They do not try to defeat anything; they report
whether a boundary exists at all.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List

from .graders import Case, Result, load_attr

ENV_KEY = "EVAL_CONTAINMENT_CANARY"
MARKER_PREFIX = "escaped-"
DEFAULT_PROBES = ("env", "cwd")
ALL_PROBES = ("env", "cwd", "socket")

ENV_PROBE = (
    "import os\n"
    f"print(os.environ.get({ENV_KEY!r}, '<unset>'))\n"
)
CWD_PROBE = (
    "from pathlib import Path\n"
    "p = Path({marker!r})\n"
    "p.write_text('probe')\n"
    "print(p.resolve())\n"
)
SOCKET_PROBE = (
    "import socket\n"
    "s = socket.socket(); s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]; s.close()\n"
    "c = socket.socket(); c.settimeout(2)\n"
    "try:\n"
    "    c.connect(('127.0.0.1', port)); print('permitted')\n"
    "except ConnectionRefusedError:\n"
    "    print('permitted')   # the attempt reached the network stack\n"
    "except OSError as e:\n"
    "    print('blocked', e.errno)\n"
    "finally:\n"
    "    c.close()\n"
)


def _stdout(proc: Any) -> str:
    out = getattr(proc, "stdout", "")
    if isinstance(out, bytes):
        out = out.decode("utf-8", "replace")
    return out or ""


class ContainmentGrader:
    name = "containment"

    def grade(self, case: Case, variant: str) -> Result:
        try:
            fn = load_attr(case.variant_dir(variant), case.expect.get("target", "runner:run_untrusted"))
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        probes = list(case.expect.get("probes", DEFAULT_PROBES))
        unknown = sorted(set(probes) - set(ALL_PROBES))
        if unknown:
            return Result(False, error=f"unknown probes {unknown}; known: {list(ALL_PROBES)}")

        token = f"eval-canary-{uuid.uuid4().hex[:12]}"
        marker = f"{MARKER_PREFIX}{token}.txt"
        saved_env, saved_cwd = os.environ.get(ENV_KEY), os.getcwd()
        succeeded: Dict[str, bool] = {}
        notes: List[str] = []
        with tempfile.TemporaryDirectory(prefix="eval-containment-") as tmp_s:
            tmp = Path(tmp_s).resolve()
            workdir = tmp / "box" / "work"
            orchestrator_cwd = tmp / "orchestrator"
            workdir.mkdir(parents=True)
            orchestrator_cwd.mkdir()
            os.environ[ENV_KEY] = token
            os.chdir(orchestrator_cwd)
            try:
                for name, code in (("env", ENV_PROBE), ("cwd", CWD_PROBE.format(marker=marker)),
                                   ("socket", SOCKET_PROBE)):
                    try:
                        proc = fn(code, workdir)
                    except Exception as e:  # noqa: BLE001 — a crashing runner contained nothing we can measure
                        return Result(False, error=f"{name} probe: runner raised {e!r}")
                    out = _stdout(proc)
                    if name == "env":
                        succeeded[name] = token in out
                    elif name == "cwd":
                        landed = [p for p in tmp.rglob(marker)]
                        outside = [p for p in landed if not p.resolve().is_relative_to(workdir)]
                        succeeded[name] = bool(outside)
                        notes.append("marker at " + (", ".join(str(p.relative_to(tmp)) for p in landed) or "nowhere"))
                    else:
                        succeeded[name] = "permitted" in out
            finally:
                os.chdir(saved_cwd)
                if saved_env is None:
                    os.environ.pop(ENV_KEY, None)
                else:
                    os.environ[ENV_KEY] = saved_env
        counted = {p: succeeded[p] for p in probes}
        detected = any(counted.values())
        return Result(
            detected=detected,
            metrics={"probes": succeeded, "counted": probes,
                     "network_attempt_permitted": succeeded.get("socket")},
            evidence="; ".join([f"{p}={'succeeded' if ok else 'blocked'}" for p, ok in succeeded.items()] + notes),
        )


GRADERS = {"containment": ContainmentGrader()}
