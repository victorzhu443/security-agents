def build(document_text: str):
    return [{"role": "user", "content": f"Summarize:\n{document_text}"}]
