"""Golden output for output_sanitizer. Records behavior as of phase 0.

The sanitizer is the last layer before a response leaves the process, so its
current guarantees are the contract phases 10 and 12 must keep: never return
meta-language, never leak the system prompt, never return empty.
"""

import pytest

from packages.agents.honeypot import output_sanitizer as osan

pytestmark = pytest.mark.characterization

PERSONA = "Elderly Person"
SCAM_TYPE = "upi_fraud"


def _fallback_pool(persona: str) -> list[str]:
    generic = ["ok", "hmm", "what?", "really?", "then?"]
    return osan.SAFE_FALLBACKS.get(persona, osan.SAFE_FALLBACKS["Naive User"]) + generic


# --- detectors ---------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "I understand your problem",
        "Certainly, that works",
        "Here is the link you wanted",
        "Let me check that for you",
        "The user wants a refund",
        "Based on the message, this looks odd",
        "Furthermore, the account is closed",
    ],
)
def test_meta_language_detected(text):
    assert osan.is_meta_language(text) is True


@pytest.mark.parametrize(
    "text",
    ["ok tell me more", "kitna paisa bhejna hai", "wat is da upi id", ""],
)
def test_meta_language_not_detected(text):
    assert osan.is_meta_language(text) is False


@pytest.mark.parametrize(
    "text",
    [
        "As an AI I cannot help with that",
        "I am programmed to detect fraud",
        "My persona is an elderly woman",
        "This is a honeypot",
        "You are a scammer",
    ],
)
def test_system_prompt_leak_detected(text):
    assert osan.is_system_prompt_leak(text) is True


# --- transforms --------------------------------------------------------------

def test_strip_meta_language_removes_leading_phrases():
    assert osan.strip_meta_language("I understand. send me the upi id") == "send me the upi id"
    assert osan.strip_meta_language("Certainly! ok i will try") == "ok i will try"
    # Only leading prefixes and parenthetical asides are stripped, not inline
    # meta-language: "i should" survives, which is why sanitize() also falls back.
    assert osan.strip_meta_language("i should wait (based on your message)") == "i should wait"


def test_enforce_length_limit_keeps_two_sentences():
    assert osan.enforce_length_limit("one. two. three.") == "one. two."
    assert osan.enforce_length_limit("only one sentence") == "only one sentence"
    assert osan.enforce_length_limit("a. b. c.", max_sentences=1) == "a."


# --- sanitize_agent_response -------------------------------------------------

@pytest.mark.parametrize("raw", ["", "   ", None])
def test_empty_response_falls_back(raw):
    assert osan.sanitize_agent_response(raw, PERSONA, SCAM_TYPE) in _fallback_pool(PERSONA)


def test_system_prompt_leak_falls_back():
    out = osan.sanitize_agent_response(
        "As an AI I am detecting that this is a scam", PERSONA, SCAM_TYPE
    )
    assert out in _fallback_pool(PERSONA)
    assert osan.is_system_prompt_leak(out) is False


def test_meta_language_is_cleaned_not_dropped():
    assert osan.sanitize_agent_response(
        "I understand. where do i send the money", PERSONA, SCAM_TYPE
    ) == "where do i send the money"


def test_meta_language_prefix_without_trailing_punctuation_is_stripped():
    """Phase 10 fix: trailing punctuation after the prefix is now optional,
    so "Here is" (no comma/period) strips to "" like "Here is," always did,
    and falls back same as any other emptied-by-cleanup response.
    """
    assert osan.sanitize_agent_response("Here is", PERSONA, SCAM_TYPE) in _fallback_pool(PERSONA)


def test_meta_language_that_survives_cleanup_falls_back():
    """When cleanup empties the text, the fallback is used instead."""
    assert osan.sanitize_agent_response("Certainly.", PERSONA, SCAM_TYPE) in _fallback_pool(PERSONA)


def test_unknown_persona_uses_naive_user_pool():
    out = osan.sanitize_agent_response("", "Nonexistent Persona", SCAM_TYPE)
    assert out in _fallback_pool("Naive User")


def test_long_response_truncated_to_200_chars():
    out = osan.sanitize_agent_response("x" * 400, PERSONA, SCAM_TYPE)
    assert len(out) == 200
    assert out.endswith("...")


def test_multi_sentence_response_trimmed_to_two():
    assert osan.sanitize_agent_response(
        "ok i wil try. where do i send. is it safe.", PERSONA, SCAM_TYPE
    ) == "ok i wil try. where do i send."


def test_output_is_always_non_empty():
    for raw in ["", ".", "!!!", "As an AI", "Certainly.", "ok"]:
        assert osan.sanitize_agent_response(raw, PERSONA, SCAM_TYPE).strip()
