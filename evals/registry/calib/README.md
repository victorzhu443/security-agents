# Calibration registry — `security.calib.<class>.v<N>`

One entry per vulnerability class whose calibration dataset has been built from public,
already-patched advisories in third-party projects (the plan's Phase 1; first class P4
egress / SSRF, CWE-918). The entry is the **pre-registration**: it names the primary metric,
pins the two prompt texts by hash, and carries the seal of the test split before the first
paid run. `evals.registry.load_registry()` globs only the top level of `evals/registry/`,
so these entries are loaded by `evals/calib/runner.py` (`load_calib_registry`), not by the
detector runner.

The tasks are Harbor task directories (`evals/calib/<class>/tasks/<id>/`, schema 1.4) run by
`harbor run`; this registry does not duplicate their `task.toml` metadata, it indexes them.

## Entry fields (`evals/registry/calib/<class>.yaml`)

| field | type | meaning |
|---|---|---|
| `id` | string | `security.calib.<class>.v<version>`; bump `version` when the task set, splits or grader semantics change |
| `version` | int | see `id` |
| `name` | string | `calib.<class>` |
| `property` | string | `P4` … (Layer 0 row) |
| `cwe` | string | `CWE-918` |
| `description` | string | the invariant being calibrated, categorical |
| `source` | string | `advisory` (Layer 7 rule 1; every task record carries the same value) |
| `tasks` | string | path, relative to the repo root, of the `tasks.jsonl` listing every built task (`evals/calib/<class>/tasks.jsonl`) |
| `tasks_dir` | string | path of the Harbor task directories (`evals/calib/<class>/tasks`) |
| `harbor_version` | string | the `harbor` release the task dirs were validated against (`0.27.0`) |
| `splits.seed` | int | the seed `evals.calib.split.assign` was run with |
| `splits.fractions` | list of 3 floats | train / validation / test, `[0.5, 0.2, 0.3]` |
| `splits.counts` | map | `{train: n, validation: n, test: n, negatives: n}` after the validity gate |
| `splits.test_hash` | string | **the seal**: `evals.calib.split.seal_hash(...)` over the sorted test task ids and the content hash of each test task directory; `calib-split --check` recomputes it and fails on any difference; empty string until step 7 |
| `splits.sealed_at` | string | ISO date the seal was written, `""` until then |
| `splits.manifests` | map | `{train: path, validation: path, test: path}` of the Harbor `dataset.toml` manifests `split.py` emits |
| `primary_metric` | map | `{name: "class_blind_recall_and_fpr", split: "test", condition: "class-blind", ci: "wilson95"}` — the one pre-registered number; everything else is secondary |
| `secondary_metrics` | list | `[class_aware_recall, fix, claim_fidelity, scope_safety, cost_usd_per_task, pass_pow_k]` |
| `graders` | list | `[recall, fix, claim_fidelity, scope_safety]` (+ `fp` on negatives); the verifier writes them as labeled rewards |
| `prompt_hashes` | map | `{class-blind: {system: sha256, user: sha256}, class-aware: {system: sha256, user: sha256}}` of the exact prompt texts `evals/agent/prompts.py` produces for this class (`prompts.prompt_hashes`); a run whose hashes differ from the entry is labelled `prompt_drift` in its summary |
| `conditions` | list | the pre-registered conditions: `[class-blind, class-aware, class-blind+no_verifier]` |
| `cutoffs` | string | path of `evals/calib/cutoffs.yaml` |
| `anchor` | list | the 8 train task ids rerun monthly for provider drift (empty until step 7) |
| `exclusions` | string | path of `evals/calib/<class>/exclusions.jsonl` (every excluded candidate, categorical reason) |
| `owner_agent` | string | `agents/egress.md` (class-aware) — the class-blind spec is `agents/generic.md` |
| `canary` | string | verbatim `evals/registry/CANARY.txt`; also in every `task.toml` `[metadata].canary` and every `tasks.jsonl` line |

## Why `test_hash` is one-way

`python -m evals calib-split` writes `test_hash` once. A second run that would change it
refuses unless `--unseal-test` is passed, and `--unseal-test` is also required for any
`calib-run --split test`, so a test-set touch is always a deliberate, logged act. The hash
covers the task **content** (Dockerfile, hidden patch, metadata), not only the ids: editing
a sealed task also breaks the seal.

## Commands

```bash
python -m evals calib-split [--seed N] [--check]        # assign + manifests; --check recomputes test_hash
python -m evals calib-run --model <id> --trials K --budget-usd N --condition class-blind --split train
python -m evals calib-run ... --split test --unseal-test                   # the one reported number
python -m evals calib-compare <run_a> <run_b>                              # paired bootstrap + McNemar
```
