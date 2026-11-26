from promptinject.assemble import Untrusted, build_prompt
from promptinject.defense import scrub_output

SYSTEM = "You summarize sources for an internal report."


def complete(messages):
    return next(m["content"] for m in reversed(messages) if m["role"] == "user")


def target(untrusted_text: str) -> str:
    messages = build_prompt("Summarize this source.", data=[Untrusted(untrusted_text, "source")],
                            system=SYSTEM)
    return scrub_output(complete(messages))
