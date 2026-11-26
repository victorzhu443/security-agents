from promptinject.defense import harden


def extract(chain, job_text: str, language: str = "en") -> str:
    inputs = {"job_text": harden(job_text), "language": language}
    return chain.invoke(inputs)
