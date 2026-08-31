"""Golden output for session_manager. Records behavior as of phase 0.

Sessions live in a module-level dict today; phase 7 moves them to Redis +
Postgres. These tests pin the lifecycle semantics that must survive that move:
message counting, intelligence union, scoring weights, and completion rules.
"""

import pytest

from packages.domain.investigations import session_manager as sm

pytestmark = pytest.mark.characterization

SESSION_ID = "sess-char-001"


def _msg(text: str, sender: str = "scammer") -> dict:
    return {"sender": sender, "text": text, "timestamp": 1000.0}


# --- lifecycle ---------------------------------------------------------------

def test_create_session_shape():
    session = sm.create_session(SESSION_ID)
    assert set(session) == {
        "sessionId", "scamDetected", "scamType", "mlScamConfidence", "mlScamLabel",
        "sentiment", "language", "persona", "conversationHistory",
        "extractedIntelligence", "startTime", "messageCount", "isComplete",
        "callbackSent",
    }
    assert set(session["extractedIntelligence"]) == {
        "bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords",
    }


def test_get_or_create_is_idempotent():
    first = sm.get_or_create_session(SESSION_ID)
    assert sm.get_or_create_session(SESSION_ID) is first


def test_add_message_counts_agent_reply_separately():
    sm.get_or_create_session(SESSION_ID)

    sm.add_message(SESSION_ID, _msg("hello"))
    assert sm.sessions[SESSION_ID]["messageCount"] == 1

    sm.add_message(SESSION_ID, _msg("send money"), agent_response="how much?")
    assert sm.sessions[SESSION_ID]["messageCount"] == 3

    senders = [m["sender"] for m in sm.sessions[SESSION_ID]["conversationHistory"]]
    assert senders == ["scammer", "scammer", "agent"]


def test_add_message_on_unknown_session_is_a_noop():
    sm.add_message("does-not-exist", _msg("hi"))  # must not raise
    assert "does-not-exist" not in sm.sessions


def test_get_session_returns_a_deep_copy():
    sm.get_or_create_session(SESSION_ID)
    snapshot = sm.get_session(SESSION_ID)
    snapshot["extractedIntelligence"]["upiIds"].append("leak@okaxis")
    assert sm.sessions[SESSION_ID]["extractedIntelligence"]["upiIds"] == []
    assert sm.get_session("does-not-exist") is None


def test_set_scam_detected_stores_ml_signals():
    sm.get_or_create_session(SESSION_ID)
    sm.set_scam_detected(
        SESSION_ID, True, "upi_fraud", "Naive User",
        ml_confidence=0.91, ml_label="spam", sentiment="NEGATIVE", language="hi",
    )
    session = sm.sessions[SESSION_ID]
    assert (session["scamDetected"], session["scamType"], session["persona"]) == (
        True, "upi_fraud", "Naive User",
    )
    assert (session["mlScamConfidence"], session["mlScamLabel"]) == (0.91, "spam")
    assert (session["sentiment"], session["language"]) == ("NEGATIVE", "hi")


# --- intelligence merge ------------------------------------------------------

def test_add_intelligence_unions_and_deduplicates():
    sm.get_or_create_session(SESSION_ID)
    sm.add_intelligence(SESSION_ID, {"upiIds": ["a@okaxis", "b@ybl"]})
    sm.add_intelligence(SESSION_ID, {"upiIds": ["b@ybl", "c@paytm"]})

    intel = sm.sessions[SESSION_ID]["extractedIntelligence"]
    assert sorted(intel["upiIds"]) == ["a@okaxis", "b@ybl", "c@paytm"]


def test_add_intelligence_ignores_unknown_and_non_list_keys():
    sm.get_or_create_session(SESSION_ID)
    sm.add_intelligence(SESSION_ID, {"amounts": ["rs 500"], "organizations": "SBI"})
    intel = sm.sessions[SESSION_ID]["extractedIntelligence"]
    assert "amounts" not in intel and "organizations" not in intel


def test_intelligence_score_weights():
    assert sm.get_intelligence_score({}) == 0
    assert sm.get_intelligence_score({"upiIds": ["a"]}) == 30
    assert sm.get_intelligence_score({"bankAccounts": ["a"]}) == 25
    assert sm.get_intelligence_score({"phoneNumbers": ["a"]}) == 20
    assert sm.get_intelligence_score({"phishingLinks": ["a"]}) == 15
    assert sm.get_intelligence_score(
        {"upiIds": ["a"], "phoneNumbers": ["b"], "bankAccounts": ["c"], "phishingLinks": ["d"]}
    ) == 90


# --- completion rules --------------------------------------------------------

def _seed(turns: int, intel: dict | None = None, **flags) -> None:
    session = sm.get_or_create_session(SESSION_ID)
    session["messageCount"] = turns * 2
    session["conversationHistory"] = [_msg("filler message here")] * (turns * 2)
    if intel:
        sm.add_intelligence(SESSION_ID, intel)
    session.update(flags)


def test_should_complete_is_false_before_eight_turns():
    _seed(turns=3, intel={"upiIds": ["a@okaxis", "b@ybl", "c@paytm"]})
    assert sm.should_complete(SESSION_ID) is False


def test_should_complete_on_early_disengagement():
    _seed(turns=3)
    sm.sessions[SESSION_ID]["conversationHistory"].append(_msg("scam bye"))
    assert sm.should_complete(SESSION_ID) is True


def test_disengagement_needs_a_short_non_agent_message():
    _seed(turns=3)
    history = sm.sessions[SESSION_ID]["conversationHistory"]
    history.append(_msg("i think this might be a scam actually"))  # too long
    assert sm.detect_disengagement(sm.sessions[SESSION_ID]) is False
    history.append(_msg("stop bye", sender="agent"))  # agent messages ignored
    assert sm.detect_disengagement(sm.sessions[SESSION_ID]) is False


def test_should_complete_on_high_intel_score():
    _seed(turns=8, intel={"upiIds": ["a@okaxis", "b@ybl", "c@paytm"]})  # score 90
    assert sm.should_complete(SESSION_ID) is True


def test_low_score_keeps_running_until_fifteen_turns():
    _seed(turns=10, intel={"phishingLinks": ["http://x.xyz"]})  # score 15
    assert sm.should_complete(SESSION_ID) is False


def test_moderate_score_completes_at_twelve_turns():
    _seed(turns=12, intel={"upiIds": ["a@okaxis"], "phoneNumbers": ["9876543210"]})  # 50
    assert sm.should_complete(SESSION_ID) is True


def test_should_complete_at_max_turns():
    _seed(turns=25)
    assert sm.should_complete(SESSION_ID) is True


@pytest.mark.parametrize("flag", ["isComplete", "callbackSent"])
def test_terminal_flags_short_circuit(flag):
    _seed(turns=1, **{flag: True})
    assert sm.should_complete(SESSION_ID) is True


def test_should_complete_on_unknown_session():
    assert sm.should_complete("does-not-exist") is True


def test_mark_helpers_and_duration():
    sm.get_or_create_session(SESSION_ID)
    sm.mark_complete(SESSION_ID)
    sm.mark_callback_sent(SESSION_ID)
    assert sm.sessions[SESSION_ID]["isComplete"] is True
    assert sm.sessions[SESSION_ID]["callbackSent"] is True
    assert sm.get_engagement_duration(SESSION_ID) >= 0
    assert sm.get_engagement_duration("does-not-exist") == 0
