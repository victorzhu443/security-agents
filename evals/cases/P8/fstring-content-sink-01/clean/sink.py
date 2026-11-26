from promptinject.defense import harden


def build(document_text: str):
    return [{"role": "user", "content": f"Summarize:\n{harden(document_text)}"}]
