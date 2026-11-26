from promptinject.assemble import Untrusted, build_prompt
from promptinject.defense import scrub_output


def answer(llm, question: str, page_text: str) -> str:
    messages = build_prompt(f"Answer this question from the page: {question}",
                            data=[Untrusted(page_text, "page")],
                            system="Answer the question from the page.")
    return scrub_output(llm.invoke(messages).content)
