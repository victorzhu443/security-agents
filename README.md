# security-agents

A small, real security toolkit built against Victor's own projects, covering two
skill areas:

1. **Security tooling** — Semgrep (SAST), fuzzing (property-based + coverage-guided),
   and runbooks for Burp Suite and Metasploit.
2. **Prompt injection / jailbreak** — a defensive robustness harness that red-teams
   our own LLM apps against documented injection categories and hardens them.

Everything here is **defensive and authorized**: it scans, fuzzes, and red-teams
code and applications we own. Nothing targets third-party systems, and the
prompt-injection work tests our apps' resistance — it is not a jailbreak kit.

## Layout

```
secprim/       shared security primitives the fixes are built on:
               boundary (validate shape/path), bounded (size/xml/zip ceilings, ReDoS probe),
               child_env (allow-listed subprocess env), secrets (require_secret, 0600 writes),
               safe_fetch (pinned, egress-validated HTTP; closes DNS-rebinding)
semgrep/       custom SAST rules (incl. an LLM01 prompt-sink rule) + scan.sh runner
promptinject/  corpus + harness + defenses + assemble.py (the one prompt chokepoint)
fuzzing/       fuzz_lib.py (Hypothesis assert_robust + size_sweep cost property),
               atheris_harness.py + run_atheris.sh (coverage-guided; Docker fallback on macOS),
               seeds/<target>/ corpora
runbooks/      burp-suite.md (web apps), metasploit-lab.md (isolated lab)
PLAN.md        per-project × per-skill plan, with step-by-step tasks and status
ROOT-CAUSES.md every finding across the repos → 9 root causes → a solution each
DESIGN.md      the exhaustive system design: current state, architecture decisions,
EVALS-PLAN.md  evals from the ground up: properties → oracles → case corpus → metrics → gates → agent eval
agents/        specialized security agents, one per property, as Claude Code agent files (roster in agents/README.md)
               per-root-cause component design, feature selection, edit manifest
```

## Quick start

```bash
pip install -r requirements.txt

# SAST across the projects (custom rules + registry packs)
semgrep/scan.sh ../research-replication-agent ../smart-dispatch ../study-hub

# Prompt-injection demo (no API cost): vulnerable stub vs hardened
python -m promptinject.harness

# Fuzzing and injection tests live in each project's tests/security/
```

## What's demonstrated where

| Project | Semgrep | Fuzzing | Prompt-injection | Burp/MSF |
|---|---|---|---|---|
| research-replication-agent | ✓ custom + packs | ✓ paper/JSON parser | ✓ paper-text input path | — |
| smart-dispatch | ✓ Django/OWASP | ✓ ERCOT ingest parser | ✓ RAG `/query` | ✓ Burp |
| firstplay | ✓ full web stack | ✓ scrape parser | ✓ autofill source | ✓ Burp |
| study-hub | ✓ custom + packs | ✓ web/Canvas parsers | — (no model sink) | — |
| (lab) | — | — | — | ✓ Metasploit lab |

See `PLAN.md` for the task-level breakdown and current status of each cell.

## Evals

`evals/` measures the toolkit instead of trusting it, in the layout the labs' eval
suites share (registry, tasks as data, deterministic graders, per-sample records,
Wilson CIs, pass@k / pass^k, eval cards, contamination canary). The design and the
conventions it follows are in `EVALS-PLAN.md` (Layer 6 is the format).

```
evals/registry/<name>.yaml   9 evals, one per property: security.boundary.v1 … security.defaults.v1
evals/registry/tasks.jsonl   every task flattened (generated; CI fails if stale)
evals/cases/<P>/<id>/        case.yaml + vuln/ + clean/  (54 tasks, 24 historical misses)
evals/graders*.py            the oracles; evals/metrics.py the statistics
evals/cards/<name>.md        the eval card per property
evals/results/<run_id>/      samples.jsonl · summary.json · report.md  (gitignored; CI artifact)
```

```bash
python -m evals list                                   # evals, task counts, graders
python -m evals run --strict                           # all 9 evals; exit 1 on any failed task
python -m evals run --eval egress --trials 3           # one eval, pass@k and pass^k over trials
python -m evals card egress                            # the eval card
python -m evals build-tasks                            # after adding or editing a case
```

The numbers live in `evals/results/<run_id>/summary.json` (`overall` and per-eval
blocks: `n`, `recall`, `precision`, each with `*_ci95`), pointed to by
`evals/results/latest.json`; CI uploads the run directory as the `evals-run`
artifact. Mutation-testing results (`evals/mutate.py`) are the
`evals/results/mutation-*.md` tables.

## Honest scope

- Semgrep, fuzzing, and the prompt-injection harness are **wired into the real
  projects and runnable now** (real findings, real tests).
- Burp and Metasploit are **runbooks**: they need a running app / an isolated VM
  you drive by hand. They are planned exercises, not automated here, and the docs
  say so.
