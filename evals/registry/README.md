# Eval registry

Every eval is a named, versioned entry here (the OpenAI Evals `registry/evals/*.yaml` /
BIG-bench `task.json` convention, EVALS-PLAN.md Layer 6). The tasks themselves stay as
data in `evals/cases/<P>/<case>/case.yaml`; this directory is the index over them.

```
<name>.yaml     one entry per property (boundary, cost, containment, egress, secrets,
                access, supply, llmsep, defaults)
CANARY.txt      the contamination canary, defined once
tasks.jsonl     every case flattened to one JSON record — generated, committed
```

## Entry fields

| field | meaning |
|---|---|
| `id` | `security.<name>.v<version>`; bump `version` when the task set or grader semantics change |
| `property` | P1–P9, the Layer 0 row the eval measures |
| `description` | the invariant, from Layer 0 |
| `task_dir` | `cases/P<n>` relative to `evals/` — every `case.yaml` under it is a task |
| `graders` | the grader names its cases actually use (a test checks the two agree) |
| `metrics` | `recall` (vuln/ detected) and `precision` (clean/ not flagged), each with a Wilson 95% CI |
| `split` | `build` (used to tune rules and defenses) or `heldout` (sealed, Phase 4) |
| `owner_agent` | the `agents/*.md` spec scored on this eval's tasks in Phase 7 |
| `canary` | the string in `CANARY.txt`, verbatim |

## Why the canary exists

`CANARY.txt` holds one GUID string. It is embedded in every registry entry, every
`case.yaml` and every line of `tasks.jsonl`. This is BIG-bench's convention for
detecting a model that was trained on the eval set: a model that can complete or
reproduce the canary string has seen this corpus, and its scores on it then measure
memorization, not the security property. The string is deliberately unique and
meaningless so it cannot occur by chance, and it says in plain words that the data
must not be used for training, which is the signal crawlers and dataset curators
filter on.

The case directories are intentionally vulnerable code; the canary does not make them
safe to train on, it makes it possible to notice afterwards that someone did.

Rules: never change the GUID (it would reset the detection history); every new case
must carry it (`python -m evals build-tasks` refuses one that does not, and
`tests/test_evals_format.py` checks all three places); keep it out of prose files such
as the cards and this README, so that a grep for the GUID hits dataset files only.

## Commands

```bash
python -m evals list                  # the table: evals, task counts, graders
python -m evals build-tasks           # regenerate tasks.jsonl after adding or editing a case
python -m evals build-tasks --check   # exit 1 if tasks.jsonl is stale (CI runs this)
python -m evals run --eval egress     # run one eval (name, id or property)
python -m evals card egress --write   # regenerate its card in evals/cards/
```
