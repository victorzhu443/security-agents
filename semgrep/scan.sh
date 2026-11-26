#!/usr/bin/env bash
# Run the project's custom rules plus curated registry packs over one or more paths.
# Usage: semgrep/scan.sh <path> [path...]
# Env:   SARIF=1 to also emit results.sarif (for GitHub code scanning).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PATHS=("$@")
[ ${#PATHS[@]} -eq 0 ] && PATHS=(".")

# Custom rules always run offline. Registry packs (p/...) need network the first
# time; they are the high-signal subset for these stacks.
CONFIGS=(--config "$HERE/rules.yml" --config p/python --config p/secrets)
# Add Django/owasp packs when scanning the web apps.
case "${PATHS[*]}" in
  *smart-dispatch*|*firstplay*) CONFIGS+=(--config p/django --config p/owasp-top-ten) ;;
esac

ARGS=(scan "${CONFIGS[@]}" --metrics off
      --exclude .venv --exclude node_modules --exclude '*.min.js'
      --exclude '*.lock' --exclude data_cache --exclude runs)
[ "${SARIF:-0}" = "1" ] && ARGS+=(--sarif --output "$HERE/results.sarif")

echo "semgrep ${PATHS[*]}"
semgrep "${ARGS[@]}" "${PATHS[@]}"
