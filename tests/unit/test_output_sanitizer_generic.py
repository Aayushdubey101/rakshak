"""output_sanitizer.sanitize() — the general-purpose entry point task.md phase
10 requires ("the output sanitizer applies to all agent output, not just
honeypot output"). sanitize_agent_response() is honeypot's caller of it,
covered separately by tests/unit/test_char_sanitizer.py."""

from packages.agents.honeypot import output_sanitizer as osan


def test_empty_text_uses_the_caller_supplied_fallback():
    assert osan.sanitize("", fallback="safe default") == "safe default"


def test_system_prompt_leak_uses_the_fallback():
    assert osan.sanitize("As an AI I cannot help", fallback="safe default") == "safe default"


def test_meta_language_is_cleaned_not_dropped():
    assert osan.sanitize("I understand. here are the actions", fallback="x") == "here are the actions"


def test_max_sentences_zero_disables_the_sentence_cap():
    text = "First sentence. Second sentence. Third sentence."
    assert osan.sanitize(text, fallback="x", max_sentences=0) == text


def test_default_two_sentence_cap_still_applies_when_requested():
    text = "First sentence. Second sentence. Third sentence."
    assert osan.sanitize(text, fallback="x", max_sentences=2) == "First sentence. Second sentence."


def test_long_text_truncated_to_max_chars():
    out = osan.sanitize("x" * 900, fallback="x", max_sentences=0, max_chars=500)
    assert len(out) == 500
    assert out.endswith("...")


def test_check_meta_language_false_lets_explanatory_prose_through():
    # "This message" trips honeypot's meta-language patterns; an explanatory
    # agent (protection/investigation) legitimately needs to say it.
    text = "This message shows signs of a scam."
    assert osan.sanitize(text, fallback="x", max_sentences=0, check_meta_language=False) == text


def test_check_meta_language_false_still_blocks_system_prompt_leaks():
    out = osan.sanitize(
        "As an AI I am detecting this", fallback="safe default", check_meta_language=False,
    )
    assert out == "safe default"


def test_sanitize_agent_response_still_delegates_correctly():
    # sanitize_agent_response must keep its 200-char / 2-sentence / persona-fallback contract.
    out = osan.sanitize_agent_response("x" * 400, "Naive User", "upi_fraud")
    assert len(out) == 200
