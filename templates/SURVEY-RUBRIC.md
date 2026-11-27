# Open-source survey — shared rubric (read-only; no installs, no credentials, no code changes)

Standing template for every component survey. Copy the context paragraph, fill in the
component, hand one copy to each surveyor. The first use (2026-11-27, six components, 160
candidates) is merged in `SURVEY.md`; re-run this rubric before each new vulnerability class.

Context: we are building a defensive security agent that finds vulnerabilities and proposes fixes
in Python repositories, measured by lab-grade evals (see `PLAN.md`, `EVALS-PLAN.md`, and the
"Framework decision" and "Phase 1 design" sections of the current plan). We have decided to build
on **Harbor** (harbor-framework/harbor) as the task/sandbox/runner layer. Principle: **adopt data,
infrastructure and baselines freely; build only the contribution** (security graders, per-class
agents, measurement discipline). Anything that overlaps the contribution is *referenced*, not
adopted.

## Your job
Survey ONE component (given in your prompt). Timebox: about one hour of searching and reading.
Find the real candidates, verify each against its own repo/docs (not from memory), score, decide.

Where to look: GitHub topics and "awesome-*" lists for the component; Harbor's dataset registry
(`registry.json` in harbor-framework/harbor, `harbor datasets list` docs); UK AISI Inspect Evals
(UKGovernmentBEIS/inspect_evals); Papers with Code datasets; OSV.dev; references of the papers we
trust (SWE-agent, τ-bench, SWE-bench Verified, CVEfixes). Prefer primary sources.

## Score every candidate on six criteria (0–2 each; record the evidence, one short phrase)
1. **Maintained** — commits in the last 6 months; issues answered. (2 active / 1 slow / 0 dead)
2. **License** — Apache-2.0, MIT, BSD = 2; copyleft usable as a tool = 1; unclear/none = 0.
3. **Fit** — does the exact thing we need (2), an adjacent thing (1), tangential (0).
4. **Kind** — data, infrastructure or baseline = 2 (take); competing implementation of our
   contribution = 0 (reference only); mixed = 1.
5. **Quality signal** — tests + docs + paper/users (2), some (1), none (0).
6. **Switching cost** — drop-in (2), adapter needed (1), re-architecture (0).

## Decision per candidate
`adopt` (we use it in Phase 1 or the next class) · `reference` (read/learn/compare, do not depend)
· `reject` (with the one-line reason). Rejections are as valuable as adoptions.

## Output
Write `survey-<component>.md` in the session's scratch directory (never in the repo):
a Markdown table — name | link | what it does (one line, categorical) | maintained | license |
fit | kind | quality | switching | total | decision | reason — sorted by decision then total;
then a short "Recommended for Phase 1" paragraph (≤ 5 lines) and "Gaps: nothing found for …".
Then report back in ≤ 25 lines: the adopt list with one line each, the top rejections and why,
and anything that changes our plan.

The merge step (one docs-only PR) consolidates the per-component tables into `SURVEY.md`:
Adopt / Reference / Reject tables, Gaps, Changes to the plan, and the per-component tables
verbatim as an appendix so scores and evidence are preserved.

## Rules
Read-only everywhere (web, GitHub, local repo). No installs, no `pip`, no cloning into the
project, no credentials, no model calls. Descriptions stay categorical and defensive (what a tool
detects or provides, never attack procedure). Python-first; note language scope per candidate.
If a tool is primarily offensive (exploitation frameworks, CTF solvers), list it under
`reference`/`reject` with "offensive capability, not our target" — do not detail it.
