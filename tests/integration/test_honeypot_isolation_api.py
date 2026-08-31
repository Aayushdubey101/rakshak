"""task.md phase 11's literal done-when: a consumer request cannot reach
persona/stalling code by any path, including a forged flag in the request
body. Exercised against the live `/api/honeypot/` endpoint — the only route
that ever wires an engagement hook.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.shared.config.settings import get_settings

API_KEY = "test_secret_key"
RESEARCHER_KEY = "test_researcher_key"
SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _honeypot_off_by_default(monkeypatch):
    """Production default: feature flag off, no researcher key configured."""
    settings = get_settings()
    monkeypatch.setattr(settings, "HONEYPOT_ENABLED", False)
    monkeypatch.setattr(settings, "HONEYPOT_RESEARCHER_KEY", None)


@pytest.fixture
def persona_code_must_not_run(monkeypatch):
    """Fails the test if a request reaches honeypot's persona/LLM-chat
    generation — the exact code path rule #8 says a consumer request must
    never automatically reach."""
    import packages.agents.honeypot.ai_agent as ai_agent

    async def _must_not_be_called(*_args, **_kwargs):
        raise AssertionError("honeypot ai_agent.generate_response was called without authorization")

    monkeypatch.setattr(ai_agent, "generate_response", _must_not_be_called)


def _post(client, session_id: str, headers: dict, body_extra: dict | None = None):
    body = {
        "sessionId": session_id,
        "message": {"sender": "scammer", "text": SCAM_TEXT},
        "conversationHistory": [],
        "metadata": {},
    }
    if body_extra:
        body.update(body_extra)
    return client.post("/api/honeypot/", json=body, headers=headers)


def test_default_config_never_engages_even_with_a_real_scam_message(client, persona_code_must_not_run):
    response = _post(client, "iso-default", headers={"x-api-key": API_KEY})

    assert response.status_code == 200
    assert response.json() == {"status": "success", "reply": "..."}


def test_forged_researcher_header_without_a_configured_key_does_not_authorize(client, persona_code_must_not_run):
    """HONEYPOT_RESEARCHER_KEY is unset, so no header value can match it."""
    response = _post(
        client, "iso-forged-header",
        headers={"x-api-key": API_KEY, "X-Researcher-Key": "anything-i-want"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "success", "reply": "..."}


@pytest.mark.parametrize("body_extra", [
    {"metadata": {"honeypot_authorized": True}},
    {"metadata": {"engage": True, "researcherKey": "test_researcher_key", "scope": "research:honeypot"}},
    {"metadata": {"confirmed_scam": True, "feature_enabled": True}},
])
def test_forged_body_fields_never_authorize_engagement(client, persona_code_must_not_run, body_extra):
    """The done-when's literal phrasing: no JSON body field — however named,
    however it apes the real credential/flag/verdict — can substitute for the
    server-side header + settings + pipeline-computed detection result."""
    response = _post(client, "iso-forged-body", headers={"x-api-key": API_KEY}, body_extra=body_extra)

    assert response.status_code == 200
    assert response.json() == {"status": "success", "reply": "..."}


def test_valid_credential_but_feature_flag_still_off_does_not_authorize(client, persona_code_must_not_run, monkeypatch):
    monkeypatch.setattr(get_settings(), "HONEYPOT_RESEARCHER_KEY", RESEARCHER_KEY)
    # HONEYPOT_ENABLED stays False from the autouse fixture above.

    response = _post(
        client, "iso-flag-off", headers={"x-api-key": API_KEY, "X-Researcher-Key": RESEARCHER_KEY},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "success", "reply": "..."}


def test_fully_authorized_researcher_request_does_engage(client, monkeypatch):
    """Contrast case: proves the gate isn't just always-closed — a real
    researcher, correctly configured, still gets a real engagement. No LLM
    provider is configured in tests, so this exercises ai_agent's own
    fallback reply, not a mocked one — a genuinely non-trivial reply either way."""
    settings = get_settings()
    monkeypatch.setattr(settings, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(settings, "HONEYPOT_RESEARCHER_KEY", RESEARCHER_KEY)

    response = _post(
        client, "iso-authorized", headers={"x-api-key": API_KEY, "X-Researcher-Key": RESEARCHER_KEY},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["reply"] != "..."
    assert body["reply"].strip()
