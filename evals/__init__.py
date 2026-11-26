"""evals — measure the toolkit instead of trusting it.

Layout (see EVALS-PLAN.md):
  graders.py   deterministic pass/fail code wrapping the toolkit's oracles
  run.py       discovers evals/cases/**, grades vuln/ and clean/, writes results
  cases/       labeled corpus: <property>/<case-id>/{case.yaml, vuln/, clean/}

A case passes when the grader detects the violation in `vuln/` (recall) and does
NOT detect it in `clean/` (precision). Every grader is deterministic; no model
judges anything.
"""
