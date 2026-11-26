from promptinject.assemble import Untrusted, build_prompt

SYSTEM = ("You are a careful research assistant. Read the paper excerpt and list the "
          "claims it makes, each with the metric and the reported value.")


def messages(paper_text: str) -> list:
    return build_prompt("List the claims in this excerpt.", data=[Untrusted(paper_text, "paper")],
                        system=SYSTEM)
