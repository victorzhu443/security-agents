"""evals — measure the toolkit instead of trusting it.

Layout, in the conventions the labs' eval suites share (EVALS-PLAN.md Layer 6):

  registry/<name>.yaml   one named, versioned entry per property (id, graders, metrics,
                         split, owner agent, canary); CANARY.txt; tasks.jsonl (generated)
  cases/<P>/<id>/        the tasks as data: case.yaml + vuln/ (one planted violation)
                         + clean/ (the same code, fixed)
  graders*.py            deterministic pass/fail code wrapping the toolkit's oracles;
                         the thing being scored never grades itself
  metrics.py             wilson_ci, pass_at_k, pass_pow_k
  run.py                 python -m evals run -> results/<run_id>/{samples.jsonl,
                         summary.json, report.md} + results/latest.json
  cards.py, cards/       eval cards: task, construction, provenance, metrics, limitations,
                         contamination policy
  mutate.py              mutation testing of a project's regression net (Phase 3)
  __main__.py            python -m evals run | list | card | build-tasks

A task passes when the grader detects the violation in `vuln/` (recall) and does
NOT detect it in `clean/` (precision); recall and precision carry Wilson 95% CIs,
and runs with --trials K > 1 add pass@k and pass^k. Every grader is deterministic;
no model judges anything.
"""

# NOTE: evals/cases/ is excluded from the repository's own SAST (.semgrepignore,
# .bandit) because the vuln/ variants are intentionally insecure. The graders
# scan each case directory explicitly, so coverage of the corpus is unaffected.
