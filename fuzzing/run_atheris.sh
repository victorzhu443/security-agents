#!/usr/bin/env bash
# Coverage-guided fuzz of one function, natively if this machine can, in Docker if not.
#
#   fuzzing/run_atheris.sh <module:function> [runs]
#
#   TARGET_SRC=dir   directory that holds the module (default: cwd); e.g. the
#                    study-hub `scripts/` dir for `redact:redact`
#   PYTHON=exe       interpreter to try first (default: python3). Used only if it
#                    can `import atheris`; otherwise the Docker image is used.
#   SEEDS=dir        corpus directory (default: fuzzing/seeds/<function>/ if present)
#   ALLOWED=A,B      declared exceptions (default: the harness's builtin set)
#   DOCKER=exe       docker binary (default: docker on PATH, else /opt/homebrew/bin/docker)
#
# Corpus: fuzzing/seeds/<function>/ is checked in and read-only; libFuzzer's
# working corpus grows in fuzzing/corpus/<function>/ (gitignored).
# Findings: crash-*/timeout-*/oom-* files under fuzzing/crashes/<function>/.
# Copy a finding into fuzzing/seeds/<function>/ once the bug is fixed so the
# next run starts from it.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
SPEC=${1:?usage: run_atheris.sh <module:function> [runs]}
RUNS=${2:-20000}
TARGET_SRC=$(cd "${TARGET_SRC:-.}" && pwd)
PY=${PYTHON:-python3}
IMAGE=security-agents/atheris

ARGS=("$SPEC" --runs "$RUNS")
[[ -n "${ALLOWED:-}" ]] && ARGS+=(--allowed "$ALLOWED")

# 1. Native: any interpreter that already has atheris (Linux, or macOS with an
#    LLVM clang used for the build).
if "$PY" -c "import atheris" >/dev/null 2>&1; then
  echo "[run_atheris] native: $("$PY" --version 2>&1) ($PY)" >&2
  [[ -n "${SEEDS:-}" ]] && ARGS+=(--seeds "$SEEDS")
  cd "$ROOT"
  exec env PYTHONPATH="$ROOT:$TARGET_SRC${PYTHONPATH:+:$PYTHONPATH}" \
    "$PY" -m fuzzing.atheris_harness "${ARGS[@]}"
fi

# 2. Docker: Apple Clang ships no libFuzzer, so `pip install atheris` cannot
#    build on macOS; Linux clang does, so the fuzzer runs in a container.
DOCKER=${DOCKER:-$(command -v docker || echo /opt/homebrew/bin/docker)}
if ! "$DOCKER" info >/dev/null 2>&1; then
  echo "[run_atheris] $PY has no atheris and the Docker daemon is not reachable." >&2
  echo "[run_atheris] Start it (Docker Desktop, or: colima start) and re-run." >&2
  exit 2
fi
if ! "$DOCKER" image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "[run_atheris] building $IMAGE from fuzzing/Dockerfile.atheris (one-time)" >&2
  "$DOCKER" build -f "$HERE/Dockerfile.atheris" -t "$IMAGE" "$ROOT"
fi
case "$TARGET_SRC" in
  "$HOME"/*) ;;
  *) echo "[run_atheris] warning: $TARGET_SRC is outside \$HOME; colima / Docker Desktop" >&2
     echo "[run_atheris]          share only \$HOME by default, so it may mount empty." >&2 ;;
esac
MOUNTS=(-v "$ROOT:/work" -v "$TARGET_SRC:/target:ro")
if [[ -n "${SEEDS:-}" ]]; then
  MOUNTS+=(-v "$(cd "$SEEDS" && pwd):/seeds")
  ARGS+=(--seeds /seeds)
fi
echo "[run_atheris] docker: $IMAGE (toolkit at /work, $TARGET_SRC at /target)" >&2
exec "$DOCKER" run --rm "${MOUNTS[@]}" "$IMAGE" "${ARGS[@]}"
