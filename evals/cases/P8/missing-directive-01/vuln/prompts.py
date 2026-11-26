from promptinject.defense import harden

SYSTEM = ("You are a careful research assistant. Read the paper excerpt and list the "
          "claims it makes, each with the metric and the reported value.")


def messages(paper_text: str) -> list:
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": "List the claims in this excerpt.\n\n[paper]\n" + harden(paper_text)}]
