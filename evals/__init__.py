"""evals — measure the toolkit instead of trusting it.

Layout (see EVALS-PLAN.md):
  graders.py   deterministic pass/fail code wrapping the toolkit's oracles
  run.py       discovers evals/cases/**, grades vuln/ and clean/, writes results
  cases/       labeled corpus: <property>/<case-id>/{case.yaml, vuln/, clean/}

A case passes when the grader detects the violation in `vuln/` (recall) and does
NOT detect it in `clean/` (precision). Every grader is deterministic; no model
judges anything.
"""

# NOTE: evals/cases/ is excluded from the repository's own SAST (.semgrepignore,
# .bandit) because the vuln/ variants are intentionally insecure. The graders
# scan each case directory explicitly, so coverage of the corpus is unaffected.
