from promptinject.defense import harden, scrub_output


def target(untrusted_text: str) -> str:
    return scrub_output(f"Summarize this source for the report:\n{harden(untrusted_text)}")
