# Specialized security agents

One agent per security property (the properties are defined in `EVALS-PLAN.md` Layer 0,
the root causes in `ROOT-CAUSES.md`). Each file is a Claude Code agent definition: copy it
to a repo's `.claude/agents/` or point the `secure-project` skill at it. The skill is the
orchestrator: it runs the property agents per repo, then the verifier across repos.

| agent | property | role | spec |
|---|---|---|---|
| `boundary-agent` | P1 | Boundary agent | [boundary.md](boundary.md) |
| `cost-agent` | P2 | Bounded-cost agent | [cost.md](cost.md) |
| `sandbox-agent` | P3 | Containment agent | [sandbox.md](sandbox.md) |
| `egress-agent` | P4 | Egress agent | [egress.md](egress.md) |
| `secrets-agent` | P5 | Secrets agent | [secrets.md](secrets.md) |
| `access-agent` | P6 | Access-control agent | [access.md](access.md) |
| `supply-chain-agent` | P7 | Supply-chain agent | [supply-chain.md](supply-chain.md) |
| `llm-boundary-agent` | P8 | LLM-boundary agent | [llm-boundary.md](llm-boundary.md) |
| `hardening-agent` | P9 | Hardening agent | [hardening.md](hardening.md) |
| `verifier-agent` | P0 | Verifier agent | [verifier.md](verifier.md) |

## Contract every agent follows

- **Input:** a repo path (clean worktree), a target commit, and the agent's property.
- **Method:** locate every site where the property can be violated (sweep *all* siblings,
  not the first hit), decide per site with the property's oracle, fix through the toolkit
  primitive, add the regression test, and record a claim only when the oracle passes.
- **Output:** `security-report.json` in the schema below, one PR per repo on its own
  branch (`security/<agent>-<date>`), and a `SECURITY.md` section whose status for the
  property is copied from the report, never typed.
- **Scope safety:** touch only files the finding requires; never commit anything
  secret-shaped; never merge; never rewrite history; unrelated tests stay green.
- **Evaluation:** the agent is scored by `evals/agent/` on the corpus cases of its
  property: recall, precision, fix correctness (the case's clean twin behaviour), claim
  fidelity (every claim in the report is reproduced by the oracle), scope safety.

## Why these are artefacts

Until now the agents were session prompts. A prompt cannot be versioned, diffed, or
evaluated; an agent file can. `evals/agent/` (EVALS-PLAN Phase 7) scores each file on its
property's corpus cases, so a change to a spec shows up as a change in recall, precision,
fix correctness, claim fidelity or scope safety — the same way a change to a Semgrep rule
shows up in the detector evals.
