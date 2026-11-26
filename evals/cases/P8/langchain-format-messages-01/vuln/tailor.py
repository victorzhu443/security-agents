from langchain_core.prompts import ChatPromptTemplate


class ResumeTailor:
    def __init__(self, llm):
        self.llm = llm
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "You rewrite a resume for a target role."),
            ("human", "Resume:\n{resume_text}"),
        ])

    def tailor(self, resume_text: str) -> str:
        messages = self.prompt.format_messages(resume_text=resume_text)
        return self.llm.invoke(messages).content
