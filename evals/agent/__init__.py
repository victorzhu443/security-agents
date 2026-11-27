"""evals.agent — the agent-eval harness (EVALS-PLAN.md Phase 7).

Runs one `agents/<name>.md` spec against real-repo tasks (the four security/mutations.yaml
catalogues) inside a container (or a rlimited local clone when docker is absent), with the
model loop outside the box, and grades every trial deterministically: recall, fix
correctness, claim fidelity, scope safety. A no-model validity gate (noop must fail, the
reference fix must pass) runs before any model is called.

    types.py      the shared contracts (Task, Env, Grader, Scores, TrialResult, Provenance)
    repos.yaml    the four repos: url, pinned commit, image recipe   repos.py  clone plumbing
    prices.yaml   USD per MTok, dated
    env.py        Env: container mode + local fallback
    loop.py       the Anthropic SDK tool loop, six tools, budget guard, denial log
    tasks.py      catalogue -> Task records; test-command mapping
    graders.py    the four graders
    baselines.py  noop / reference baselines and the validity gate (offline)
    runner.py     agent-run / agent-validate -> evals/results/<run_id>/

    python -m evals agent-validate --repo all
    python -m evals agent-run --repo research-replication-agent --model claude-haiku-5-5 --trials 1 --budget-usd 5
"""
