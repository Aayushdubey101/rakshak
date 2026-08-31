"""task.md phase 10's literal done-when: a web-platform request to the
canonical investigation endpoint returns an explanation + actions, with zero
persona/stalling (honeypot) code executed.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api import main

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
AUTH_HEADERS = {"x-api-key": "test_secret_key"}


@pytest.fixture
def client():
    return TestClient(main.app)


def test_web_investigation_returns_explanation_and_actions(client):
    response = client.post(
        "/api/v1/investigations",
        json={"platform": "web", "content_type": "text", "text": SCAM_TEXT},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "scam"
    assert body["explanation"]
    assert body["recommended_actions"]
    protection_stage = next(s for s in body["stage_status"] if s["stage"] == "protection")
    assert protection_stage["state"] == "ok"


def test_web_investigation_never_touches_honeypot_persona_code(client, monkeypatch):
    """No engagement hook is wired for /api/v1/investigations, so honeypot's
    persona/LLM-chat/stalling code must never run for this path."""
    import packages.agents.honeypot.ai_agent as ai_agent

    async def _must_not_be_called(*_args, **_kwargs):
        raise AssertionError("honeypot ai_agent.generate_response was called for a plain web investigation")

    monkeypatch.setattr(ai_agent, "generate_response", _must_not_be_called)

    response = client.post(
        "/api/v1/investigations",
        json={"platform": "web", "content_type": "text", "text": SCAM_TEXT},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["explanation"]


def test_benign_web_investigation_still_returns_safe_guidance(client):
    response = client.post(
        "/api/v1/investigations",
        json={"platform": "web", "content_type": "text", "text": "hey are we still on for lunch tomorrow?"},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["explanation"]
    assert body["recommended_actions"]
