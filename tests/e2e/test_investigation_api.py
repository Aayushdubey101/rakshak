"""End to end: POST /api/v1/investigations -> one CanonicalReport, rendered
by the web serializer (task.md phase 12).

test_protection_agent.py already proves phase 10's explanation/actions
contract; this file proves the phase-12 wiring on top of it -- the response
body is exactly `packages.reports.serializers.to_web(outcome.report)`, not a
separately-serialized copy.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.reports.serializers import to_web

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
BENIGN_TEXT = "hey are we still on for lunch tomorrow?"
AUTH_HEADERS = {"x-api-key": "test_secret_key"}


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture
def captured_report(monkeypatch):
    """The same report the orchestrator actually produced, for comparing
    against the HTTP response body."""
    from packages.domain.investigations import orchestrator

    captured = {}
    real = orchestrator.investigate

    async def _recording(request, **kwargs):
        outcome = await real(request, **kwargs)
        captured["report"] = outcome.report
        return outcome

    monkeypatch.setattr("apps.api.routers.investigations.investigate", _recording)
    return captured


def test_scam_investigation_returns_a_well_formed_canonical_report(client, captured_report):
    response = client.post(
        "/api/v1/investigations",
        json={"platform": "web", "content_type": "text", "text": SCAM_TEXT},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "scam"
    assert body["risk_score"] > 0
    assert body["explanation"]
    assert body["recommended_actions"]
    assert any(s["stage"] == "protection" and s["state"] == "ok" for s in body["stage_status"])


def test_response_body_is_exactly_the_web_serializer_output(client, captured_report):
    response = client.post(
        "/api/v1/investigations",
        json={"platform": "web", "content_type": "text", "text": SCAM_TEXT},
        headers=AUTH_HEADERS,
    )

    assert response.json() == to_web(captured_report["report"])


def test_benign_investigation_is_still_one_well_formed_report(client):
    response = client.post(
        "/api/v1/investigations",
        json={"platform": "web", "content_type": "text", "text": BENIGN_TEXT},
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] in ("likely_safe", "unknown")
    assert body["explanation"]
