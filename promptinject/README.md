# Prompt-injection robustness harness

A defensive test suite that measures whether **our own** LLM applications can be
subverted by instructions hidden in the untrusted content they ingest, and a set
of mitigations that make them resist. This is the AI-safety analogue of a SAST
scan: a fixed corpus, replayed against each app's real input path, with a
deterministic pass/fail.

It is **not** a jailbreak kit. There is nothing here aimed at defeating a
third-party model's safety training or evading a safety classifier. Every case
carries a harmless unique canary so a success is unambiguous and attributable.

## Threat model

Our apps feed untrusted text to a model as *data*:

| App | Untrusted channel | If injection lands |
|---|---|---|
| research-replication-agent | the paper PDF's extracted text, HF dataset cards | a paper could steer the agent's verdict or coerce a tool call |
| smart-dispatch | RAG documents behind `/query`, user query string | a retrieved doc could rewrite the answer |
| firstplay | scraped job/application pages, autofill source fields | a page could corrupt extracted fields or exfiltrate context |

LLM01 (prompt injection) is the top OWASP LLM risk precisely because the model
cannot, by itself, tell the app's instructions from instructions smuggled in the
data. The fix is architectural; the harness proves whether we applied it.

## Loop: measure → mitigate → verify

```python
from promptinject.harness import evaluate
from promptinject.corpus import corpus
from promptinject.defense import hardened_target

def raw(untrusted):               # your app's UNDEFENDED input path
    return my_app.summarize(untrusted)

print(evaluate(raw).render())              # measure: how many land today
print(evaluate(hardened_target(raw)).render())  # verify: after harden()+scrub
```

Run the shipped demo with no API cost: `python -m promptinject.harness` (scores a
deliberately-vulnerable stub, 7/8 land) and the defended version passes 8/8.

## Files

- `corpus/__init__.py` — the test cases (LLM01 categories + a benign control).
- `harness.py` — replays the corpus through a target, scores canary leakage.
- `defense.py` — `harden()` (neutralize + spotlight) and `scrub_output()`; the
  mitigations the harness verifies.

## Limits (stated honestly)

Input framing and output scrubbing raise the cost of the easy cases; they do not
"solve" prompt injection. The durable defenses are architectural: don't give a
data-reading model dangerous tools, keep a human in the loop for side effects,
and separate the untrusted-content model from the privileged-action model. The
harness exists to keep us honest about which of those we've actually done.

References: OWASP LLM Top 10 (LLM01); Greshake et al. 2023 (indirect injection);
Microsoft "spotlighting" (2024).
