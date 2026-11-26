from langchain_core.messages import HumanMessage, SystemMessage


def answer(llm, question: str, page_text: str) -> str:
    messages = [SystemMessage(content="Answer the question from the page."),
                HumanMessage(content=f"Question: {question}\n\nPage:\n{page_text}")]
    return llm.invoke(messages).content
