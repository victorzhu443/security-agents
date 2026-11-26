from langchain_core.prompts import ChatPromptTemplate

prompt = ChatPromptTemplate.from_messages([
    ("system", "You extract structured fields from a job posting."),
    ("human", "Posting:\n{job_text}\n\nReturn JSON with title, company, location."),
])


def extract(llm, job_text: str) -> str:
    chain = prompt | llm
    return chain.invoke({"job_text": job_text})
