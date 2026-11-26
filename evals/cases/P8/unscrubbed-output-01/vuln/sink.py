from promptinject.defense import harden


def complete(prompt: str) -> str:
    return prompt          # stand-in model: a subverted model repeats what it was told


def target(untrusted_text: str) -> str:
    return complete(f"Summarize this source for the report:\n{harden(untrusted_text)}")
