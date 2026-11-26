SYSTEM = "You summarize sources for an internal report."


def complete(messages):
    # Stand-in for the model call: a subverted model does what the user turn says,
    # so surfacing the user turn is the vulnerable app's observable behaviour.
    return next(m["content"] for m in reversed(messages) if m["role"] == "user")


def target(untrusted_text: str) -> str:
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Summarize this source:\n{untrusted_text}"}]
    return complete(messages)
