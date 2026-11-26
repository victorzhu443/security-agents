from promptinject.defense import harden, scrub_output


def complete(prompt: str) -> str:
    return prompt


def target(untrusted_text: str) -> str:
    return scrub_output(complete(f"Summarize this source for the report:\n{harden(untrusted_text)}"))
