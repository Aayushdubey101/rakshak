"""Golden output for LLM behavior. Records behavior as of phase 0.

Records *the prompt actually sent* and how the reply is handled, for both
detection (`scam_detector.ai_based_detection`) and agent generation
(`ai_agent.generate_response`). This is the contract phase 3's LLM Gateway
must reproduce when Gemini becomes one provider among several.

No network: the pool is replaced with an in-process recorder.
"""

import pytest

from packages.llm.gateway import TaskKind
from packages.llm.prompts import SCAM_DETECTION_PROMPT
from packages.agents.honeypot import ai_agent
from packages.domain.risk import detector as scam_detector

pytestmark = pytest.mark.characterization


class RecordingGateway:
    """Stands in for the LLM Gateway: records prompts, returns a canned reply.

    Phase 3 moved the transport behind the gateway; the prompts asserted below
    are the same ones phase 0 recorded against the Gemini pool directly.
    """

    def __init__(self, reply: str | None = "", available: bool = True):
        self.reply = reply
        self.available = available
        self.prompts: list[str] = []
        self.tasks: list[TaskKind] = []

    def has_provider_for(self, task: TaskKind) -> bool:
        return self.available

    async def try_generate(self, task: TaskKind, prompt: str, **options) -> str | None:
        self.tasks.append(task)
        self.prompts.append(prompt)
        return self.reply


@pytest.fixture
def detection_pool(monkeypatch):
    def _install(reply, available=True):
        gateway = RecordingGateway(reply, available=available)
        monkeypatch.setattr(scam_detector, "get_gateway", lambda: gateway)
        return gateway
    return _install


@pytest.fixture
def agent_pool(monkeypatch):
    def _install(reply, available=True):
        gateway = RecordingGateway(reply, available=available)
        monkeypatch.setattr(ai_agent, "get_gateway", lambda: gateway)
        return gateway
    return _install


# --- detection: prompt sent --------------------------------------------------

async def test_detection_prompt_contract(detection_pool):
    pool = detection_pool('{"isScam": true, "confidence": 0.9, "scamType": "lottery"}')

    await scam_detector.ai_based_detection(
        "you won 25 lakh",
        [{"sender": "scammer", "text": "hello sir"}, {"sender": "agent", "text": "who is this"}],
    )

    prompt = pool.prompts[0]
    assert prompt.startswith(SCAM_DETECTION_PROMPT)
    # Phase 14: history items and the current message are both delimited and
    # neutralized (prompt-injection defense) -- conversationHistory is
    # client-supplied, so it gets the same treatment as the live message.
    assert (
        "Previous messages:\n"
        "scammer: <<<UNTRUSTED_USER_CONTENT_BEGIN>>>\nhello sir\n<<<UNTRUSTED_USER_CONTENT_END>>>\n"
        "agent: <<<UNTRUSTED_USER_CONTENT_BEGIN>>>\nwho is this\n<<<UNTRUSTED_USER_CONTENT_END>>>"
    ) in prompt
    assert "<<<UNTRUSTED_USER_CONTENT_BEGIN>>>\nyou won 25 lakh\n<<<UNTRUSTED_USER_CONTENT_END>>>" in prompt
    assert prompt.endswith("Respond with JSON only:")


async def test_detection_prompt_omits_history_block_when_empty(detection_pool):
    pool = detection_pool('{"isScam": false}')
    await scam_detector.ai_based_detection("hi", None)
    assert "Previous messages:" not in pool.prompts[0]


async def test_detection_skipped_without_a_provider(detection_pool):
    gateway = detection_pool("never used", available=False)
    assert await scam_detector.ai_based_detection("you won 25 lakh") is None
    assert gateway.prompts == []


async def test_detection_asks_for_the_structured_task(detection_pool):
    gateway = detection_pool('{"isScam": false}')
    await scam_detector.ai_based_detection("hi")
    assert gateway.tasks == [TaskKind.STRUCTURED]


# --- detection: reply handling -----------------------------------------------

@pytest.mark.parametrize(
    "reply",
    [
        '{"isScam": true, "confidence": 0.9, "scamType": "lottery", '
        '"indicators": ["prize"], "reasoning": "classic"}',
        '```json\n{"isScam": true, "confidence": 0.9, "scamType": "lottery", '
        '"indicators": ["prize"], "reasoning": "classic"}\n```',
        '```\n{"isScam": true, "confidence": 0.9, "scamType": "lottery", '
        '"indicators": ["prize"], "reasoning": "classic"}\n```',
    ],
    ids=["bare", "json_fence", "bare_fence"],
)
async def test_detection_parses_every_reply_wrapping(detection_pool, reply):
    detection_pool(reply)
    assert await scam_detector.ai_based_detection("you won 25 lakh") == {
        "isScam": True,
        "confidence": 0.9,
        "scamType": "lottery",
        "indicators": ["prize"],
        "reasoning": "classic",
        "method": "ai",
    }


async def test_detection_fills_defaults_for_missing_fields(detection_pool):
    detection_pool("{}")
    assert await scam_detector.ai_based_detection("hi") == {
        "isScam": False,
        "confidence": 0.5,
        "scamType": "other",
        "indicators": [],
        "reasoning": "Gemini AI analysis",
        "method": "ai",
    }


@pytest.mark.parametrize("reply", ["not json at all", "", None])
async def test_detection_returns_none_on_unusable_reply(detection_pool, reply):
    detection_pool(reply)
    assert await scam_detector.ai_based_detection("hi") is None


# --- agent generation: prompt sent -------------------------------------------

def _session(**overrides) -> dict:
    session = {
        "sessionId": "llm-char-001",
        "scamDetected": True,
        "scamType": "upi_fraud",
        "persona": "Naive User",
        "conversationHistory": [],
        "extractedIntelligence": {
            "bankAccounts": [], "upiIds": [], "phishingLinks": [],
            "phoneNumbers": [], "suspiciousKeywords": [],
        },
    }
    session.update(overrides)
    return session


async def test_agent_prompt_contract(agent_pool):
    pool = agent_pool('"kitna paisa bhejna hai"')

    await ai_agent.generate_response(
        _session(), {"sender": "scammer", "text": "send 500 to me@okaxis now"}
    )

    prompt = pool.prompts[0]
    assert prompt.startswith("You are role-playing as a Naive User.")
    assert "CORE OPERATIONAL RULES:" in prompt
    assert "ANTI-ASSISTANT RULES (STRICT):" in prompt
    assert "FORBIDDEN PHRASES (NEVER USE):" in prompt
    # State block, appended after the persona prompt
    assert "CURRENT CONVERSATION STATE: INITIAL_CONTACT" in prompt
    assert "EMOTIONAL PROGRESSION:" in prompt
    assert "ADAPTATION INSTRUCTIONS:" in prompt
    # Context awareness: a UPI id and an urgency word were both present
    assert "CRITICAL: Scammer shared contact/payment details" in prompt
    assert "The scammer is showing urgency/pressure" in prompt
    # Phase 14: the scammer's message is delimited and neutralized
    # (prompt-injection defense), appended last.
    assert prompt.endswith(
        "<<<UNTRUSTED_USER_CONTENT_BEGIN>>>\nsend 500 to me@okaxis now\n<<<UNTRUSTED_USER_CONTENT_END>>>"
    )


async def test_agent_prompt_carries_conversation_history(agent_pool):
    pool = agent_pool('"ok"')
    history = [
        {"sender": "scammer", "text": "hello sir"},
        {"sender": "agent", "text": "who is this"},
    ]

    await ai_agent.generate_response(
        _session(conversationHistory=history), {"sender": "scammer", "text": "pay now"}
    )

    # Phase 14: history items are delimited and neutralized too.
    assert (
        "Previous conversation:\n"
        "scammer: <<<UNTRUSTED_USER_CONTENT_BEGIN>>>\nhello sir\n<<<UNTRUSTED_USER_CONTENT_END>>>\n"
        "agent: <<<UNTRUSTED_USER_CONTENT_BEGIN>>>\nwho is this\n<<<UNTRUSTED_USER_CONTENT_END>>>"
    ) in pool.prompts[0]


async def test_agent_selects_a_persona_when_none_is_set(agent_pool):
    pool = agent_pool('"ok"')
    session = _session(persona=None, scamType="lottery")

    await ai_agent.generate_response(session, {"sender": "scammer", "text": "you won"})

    assert session["persona"] in {"Naive User", "Elderly Person"}
    assert pool.prompts[0].startswith(f"You are role-playing as a {session['persona']}.")


# --- agent generation: reply handling ----------------------------------------

async def test_agent_reply_is_humanized_and_sanitized(agent_pool):
    from packages.agents.honeypot.output_sanitizer import is_system_prompt_leak

    agent_pool('"kitna paisa bhejna hai"')
    reply = await ai_agent.generate_response(
        _session(), {"sender": "scammer", "text": "send 500 to me@okaxis"}
    )

    assert reply.strip()
    assert len(reply) <= 200
    assert is_system_prompt_leak(reply) is False


@pytest.mark.parametrize("reply", [None, "", "   "])
async def test_agent_falls_back_when_the_model_returns_nothing(agent_pool, reply):
    agent_pool(reply)
    out = await ai_agent.generate_response(
        _session(), {"sender": "scammer", "text": "send 500 now"}
    )
    # get_fallback_response collapses to the job_scam pool (see test_char_honeypot)
    assert out in ai_agent.FALLBACK_RESPONSES["job_scam"]


async def test_agent_falls_back_when_no_provider_is_available(agent_pool):
    """Losing every provider degrades the reply; it never fails the request."""
    gateway = agent_pool('"never used"', available=False)
    out = await ai_agent.generate_response(
        _session(), {"sender": "scammer", "text": "send 500 now"}
    )
    assert gateway.prompts == []
    assert out in ai_agent.FALLBACK_RESPONSES["job_scam"]


async def test_agent_asks_for_the_fast_task(agent_pool):
    gateway = agent_pool('"ok"')
    await ai_agent.generate_response(_session(), {"sender": "scammer", "text": "pay now"})
    assert gateway.tasks == [TaskKind.FAST]


async def test_agent_returns_a_canned_stall_in_delay_state(agent_pool, monkeypatch):
    """Turns 16-20 can short-circuit the model entirely with a stalling line."""
    monkeypatch.setattr(ai_agent.random, "random", lambda: 0.99)  # take the canned branch
    pool = agent_pool('"never used"')

    out = await ai_agent.generate_response(
        _session(conversationHistory=[{"sender": "scammer", "text": "pay"}] * 34),
        {"sender": "scammer", "text": "pay now"},
    )

    assert pool.prompts == []
    assert out.strip()
