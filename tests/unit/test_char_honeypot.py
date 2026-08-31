"""Golden output for honeypot behavior. Records behavior as of phase 0.

Persona selection, conversation-state progression, stalling selection, and
response-memory anti-repetition. Phase 11 moves all of this into
`packages/agents/honeypot/` intact — these tests are what "intact" means.
"""

import pytest

from packages.llm.prompts import PERSONAS, select_persona
from packages.agents.honeypot import ai_agent
from packages.agents.honeypot.conversation_states import ConversationState, StateManager
from packages.agents.honeypot.response_memory import response_memory
from packages.agents.honeypot.stalling_strategies import STALLING_TACTICS, StallingEngine

pytestmark = pytest.mark.characterization


# --- persona selection -------------------------------------------------------

PERSONA_POOLS = {
    "lottery": {"Naive User", "Elderly Person"},
    "fake_offer": {"Naive User", "Interested Buyer"},
    "bank_fraud": {"Elderly Person", "Naive User"},
    "upi_fraud": {"Naive User", "Elderly Person"},
    "phishing": {"Naive User", "Interested Buyer"},
    "other": {"Naive User", "Elderly Person", "Interested Buyer"},
}


@pytest.mark.parametrize("scam_type", sorted(PERSONA_POOLS))
def test_select_persona_stays_in_its_pool(scam_type):
    names = {select_persona(scam_type)["name"] for _ in range(40)}
    assert names <= PERSONA_POOLS[scam_type]


def test_unmapped_scam_type_uses_the_other_pool():
    """job_scam, romance_scam, crypto_scam and friends are not mapped today."""
    names = {select_persona("job_scam")["name"] for _ in range(40)}
    assert names <= PERSONA_POOLS["other"]


def test_persona_definition_shape():
    for persona in PERSONAS.values():
        assert set(persona) == {"name", "description", "traits", "responseStyle"}


# --- conversation state ------------------------------------------------------

@pytest.mark.parametrize(
    "turns,state",
    [
        (0, ConversationState.INITIAL_CONTACT),
        (2, ConversationState.INITIAL_CONTACT),
        (3, ConversationState.BUILDING_TRUST),
        (4, ConversationState.BUILDING_TRUST),
        (5, ConversationState.SHOWING_INTEREST),
        (7, ConversationState.SHOWING_INTEREST),
        (8, ConversationState.FAKE_COMPLIANCE),
        (10, ConversationState.FAKE_COMPLIANCE),
        (11, ConversationState.INTELLIGENCE_EXTRACTION),
        (15, ConversationState.INTELLIGENCE_EXTRACTION),
        (16, ConversationState.DELAY_TACTICS),
        (20, ConversationState.DELAY_TACTICS),
        (21, ConversationState.GRACEFUL_EXIT),
    ],
)
def test_state_boundaries(turns, state):
    assert StateManager.get_state(turns, intel_score=0) is state


def test_state_ignores_intel_score_today():
    """Only turn count drives the state machine; intel_score is unused."""
    assert StateManager.get_state(12, 0) is StateManager.get_state(12, 500)


@pytest.mark.parametrize("state", list(ConversationState))
def test_behavior_guidance_shape(state):
    assert set(StateManager.get_behavior_guidance(state)) == {"tone", "goal", "avoid"}


# --- stalling ----------------------------------------------------------------

def test_select_tactic_rotates_by_turn():
    categories = list(STALLING_TACTICS)
    assert [StallingEngine.select_tactic(t, 0) for t in range(len(categories))] == categories
    assert StallingEngine.select_tactic(len(categories), 0) == categories[0]


def test_stale_intel_forces_technical_difficulty():
    assert StallingEngine.select_tactic(1, gap_since_intel=4) == "TECHNICAL_DIFFICULTY"


@pytest.mark.parametrize("category", sorted(STALLING_TACTICS))
def test_stalling_message_comes_from_its_category(category):
    assert StallingEngine.get_stalling_message(category) in STALLING_TACTICS[category]


def test_unknown_category_falls_back_to_any_tactic():
    every_message = {m for msgs in STALLING_TACTICS.values() for m in msgs}
    assert StallingEngine.get_stalling_message("NO_SUCH_CATEGORY") in every_message
    assert StallingEngine.get_stalling_message(None) in every_message


# --- response memory ---------------------------------------------------------

def test_memory_keeps_only_the_last_five_responses():
    session_id = "mem-char-001"
    for i in range(7):
        response_memory.add_response(session_id, f"unique response number {i}")

    assert len(response_memory.memory[session_id]) == 5
    assert response_memory.is_too_similar(session_id, "unique response number 6") is True


def test_memory_normalizes_case_and_whitespace():
    session_id = "mem-char-002"
    response_memory.add_response(session_id, "  Send Me The UPI ID  ")
    assert response_memory.memory[session_id][0] == "send me the upi id"
    assert response_memory.is_too_similar(session_id, "send me the upi id") is True


def test_empty_memory_returns_first_candidate():
    assert response_memory.get_dissimilar_variant("fresh-session", ["a", "b"]) == "a"
    with pytest.raises(ValueError):
        response_memory.get_dissimilar_variant("fresh-session", [])


# --- agent fallbacks ---------------------------------------------------------

def test_fallback_pools_are_non_empty():
    assert all(ai_agent.FALLBACK_RESPONSES.values())


@pytest.mark.parametrize(
    "scam_type",
    ["upi_fraud", "bank_fraud", "lottery", "phishing", "romance_scam", "other", None],
)
def test_fallback_type_mapping_collapses_to_job_scam(scam_type):
    """DEFECT, recorded not fixed: `any(word in scam_type for word in key_pattern)`
    iterates the *characters* of "job_scam", so any type containing one of
    j/o/b/_/s/c/a/m maps to the job_scam pool. Nearly every type does.
    Fixing this changes responses, so it belongs to phase 10, not phase 0.
    """
    pool = ai_agent.FALLBACK_RESPONSES["job_scam"]
    assert {ai_agent.get_fallback_response(scam_type) for _ in range(30)} <= set(pool)


def test_fallback_without_a_character_match_uses_other():
    pool = ai_agent.FALLBACK_RESPONSES["other"]
    assert {ai_agent.get_fallback_response("xyz") for _ in range(30)} <= set(pool)


def test_typing_delay_is_clamped_between_200ms_and_1s():
    for text in ["", "hi", "x" * 500]:
        for persona in ["Naive User", "Elderly Person", "Interested Buyer", "Unknown"]:
            assert 200 <= ai_agent.calculate_typing_delay(text, persona) <= 1000


def test_humanize_response_keeps_text_non_empty():
    for _ in range(20):
        assert ai_agent.humanize_response("please send your account number tomorrow").strip()
    assert ai_agent.humanize_response("") == ""


def test_generate_agent_notes_summary():
    notes = ai_agent.generate_agent_notes({
        "scamType": "upi_fraud",
        "persona": "Naive User",
        "messageCount": 6,
        "extractedIntelligence": {
            "upiIds": ["a@okaxis"],
            "phoneNumbers": ["9876543210"],
            "phishingLinks": [],
        },
    })
    assert notes == (
        "Scam type: upi_fraud. Used Naive User persona. Got 1 UPI ID(s). "
        "Got 1 phone(s). 6 messages total."
    )
