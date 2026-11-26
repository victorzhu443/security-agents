def extract(chain, job_text: str, language: str = "en") -> str:
    inputs = {"job_text": job_text, "language": language}
    return chain.invoke(inputs)
