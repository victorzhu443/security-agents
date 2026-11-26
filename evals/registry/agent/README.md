# Agent-eval registry (`security.agent.<repo>.v1`)

The Phase 7 agent evals live in this subdirectory, not next to the property entries above
it, for two reasons. First, `evals.registry.load_registry()` globs only the top level and
enforces one entry per property; an agent eval spans every property its repo's catalogue
touches (P1-P9), so it cannot satisfy that rule. Second, the unit here is a repo, not a
property: the tasks are the repo's `security/mutations.yaml` at the pinned `commit`, and
`graders`/`metrics` are the four agent graders and pass@k / pass^k / cost per task.

`evals.agent.runner.load_agent_registry()` reads `*.yaml` here and rejects an entry whose
`id` is not `security.agent.<repo>.v<version>`, whose `canary` differs from `../CANARY.txt`,
whose `split` is not `build` or `source` not `real-codebase`, whose `repo` is missing from
`evals/agent/repos.yaml`, or whose `commit` differs from that file's pin.
