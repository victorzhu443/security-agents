from langchain_core.prompts import ChatPromptTemplate

from promptinject.assemble import DIRECTIVE
from promptinject.defense import harden as harden_untrusted

prompt = ChatPromptTemplate.from_messages([
    ("system", "You extract structured fields from a job posting.\n\n" + DIRECTIVE),
    ("human", "Posting:\n{job_text}\n\nReturn JSON with title, company, location."),
])


def extract(llm, job_text: str) -> str:
    chain = prompt | llm
    return chain.invoke({"job_text": harden_untrusted(job_text)})
