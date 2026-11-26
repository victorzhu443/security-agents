"""RC-8 chokepoint: untrusted content is typed, fenced, and the corpus is bound to
the real assembly path."""
import pytest

from promptinject.assemble import (Untrusted, build_prompt, render,
                                   assembled_target, DIRECTIVE)
from promptinject.corpus import CANARY, corpus
from promptinject.harness import evaluate


def test_bare_str_in_data_position_is_a_type_error():
    with pytest.raises(TypeError):
        build_prompt("Summarize", data=["this is a scraped page"])  # type: ignore[list-item]


def test_messages_carry_directive_fence_and_label():
    msgs = build_prompt("Summarize the posting.", data=[Untrusted("Great job!", "job posting")],
                        system="You extract job facts.")
    assert msgs[0]["role"] == "system" and msgs[0]["content"].startswith("You extract job facts.")
    assert DIRECTIVE in msgs[0]["content"]
    user = msgs[1]["content"]
    assert user.startswith("Summarize the posting.")
    assert "[job posting]" in user and "Great job!" in user
    assert "⟦untrusted-data" in user  # the spotlight fence from defense.harden


def test_no_data_means_no_fence_but_directive_still_present():
    msgs = build_prompt("Just answer.")
    assert "⟦untrusted-data" not in msgs[1]["content"]
    assert DIRECTIVE in msgs[0]["content"]


def test_corpus_resists_through_the_real_assembly_path():
    report = evaluate(assembled_target("Summarize this source for a replication."), corpus())
    assert report.ok, "\n" + report.render()


def test_render_flattens_roles():
    text = render(build_prompt("Q", data=[Untrusted("D")]))
    assert "<system>" in text and "<user>" in text and CANARY not in text
