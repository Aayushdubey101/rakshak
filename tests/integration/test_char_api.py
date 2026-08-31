"""Golden output for the HTTP API. Records behavior as of phase 0.

The wire contract of the current endpoint, in both STRICT_RESPONSE_MODE values.
Phase 2 must keep these responses byte-compatible while an InvestigationRequest
is built underneath; phase 6 moves the path to /api/v1/investigations and keeps
this one as a deprecated alias.

TestClient is used without a context manager on purpose: entering it would run
the startup hook, which opens a web browser (a phase-1 deletion).

Phase 11 note: honeypot engagement is now gated (task.md phase 11, rule #8) —
off by default. This file's whole point is exercising a *real* engagement, so
`_researcher_authorized` turns the feature on and `_post()` sends a valid
`X-Researcher-Key` for every request, keeping the golden behavior this file
characterizes unchanged for an authorized caller.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.shared.config.settings import get_settings

pytestmark = pytest.mark.characterization

API_KEY = "test_secret_key"
RESEARCHER_KEY = "test_researcher_key"
SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."


@pytest.fixture
def client():
    return TestClient(main.app)


@pytest.fixture(autouse=True)
def _researcher_authorized(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "HONEYPOT_ENABLED", True)
    monkeypatch.setattr(settings, "HONEYPOT_RESEARCHER_KEY", RESEARCHER_KEY)


def _post(client, session_id: str, text: str = SCAM_TEXT, headers=None):
    return client.post(
        "/api/honeypot/",
        json={
            "sessionId": session_id,
            "message": {"sender": "scammer", "text": text},
            "conversationHistory": [],
            "metadata": {},
        },
        headers={"x-api-key": API_KEY, "X-Researcher-Key": RESEARCHER_KEY} if headers is None else headers,
    )


# --- auth --------------------------------------------------------------------

def test_missing_api_key_is_rejected(client):
    response = _post(client, "api-char-401", headers={})
    assert response.status_code == 401
    assert response.json() == {
        "error": "Unauthorized",
        "message": "Invalid or missing x-api-key header",
    }


def test_wrong_api_key_is_rejected(client):
    assert _post(client, "api-char-401b", headers={"x-api-key": "nope"}).status_code == 401


# --- POST /api/honeypot/ -----------------------------------------------------

def test_strict_mode_returns_status_and_reply_only(client):
    response = _post(client, "api-char-strict")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"status", "reply"}
    assert body["status"] == "success"
    assert body["reply"].strip()


def test_strict_mode_replies_even_to_benign_text(client):
    """No scam, no agent — but the reply field is never empty."""
    body = _post(client, "api-char-benign", text="hey how are you doing today").json()
    assert body == {"status": "success", "reply": "..."}


def test_detailed_mode_is_unreachable_today(monkeypatch):
    """DEFECT recorded, not fixed: the route declares
    `response_model=HoneypotResponse` ({status, reply}), so the detailed
    STRICT_RESPONSE_MODE=False branch fails response validation and 500s.
    Only the strict shape is actually servable. Phase 12 retires the flag;
    phase 2 must not "restore" this branch by accident.
    """
    monkeypatch.setattr(get_settings(), "STRICT_RESPONSE_MODE", False)
    client = TestClient(main.app, raise_server_exceptions=False)

    assert _post(client, "api-char-detailed").status_code == 500


def test_session_accumulates_across_requests(client):
    _post(client, "api-char-multi", text="pay to scammer@okaxis now")
    _post(client, "api-char-multi", text="or call 9876543210 fast")

    intel = client.get(
        "/api/honeypot/session/api-char-multi", headers={"x-api-key": API_KEY}
    ).json()["session"]["extractedIntelligence"]

    assert intel["upiIds"] == ["scammer@okaxis"]
    assert intel["phoneNumbers"] == ["9876543210"]


def test_blank_text_still_gets_an_answer(client):
    """Phase 2 guard: blank text cannot form an InvestigationRequest, and the
    endpoint must answer anyway rather than surfacing the schema error.
    """
    assert _post(client, "api-char-blank", text="   ").json() == {
        "status": "success",
        "reply": "...",
    }


def test_malformed_body_is_a_validation_error(client):
    response = client.post(
        "/api/honeypot/", json={"sessionId": "x"}, headers={"x-api-key": API_KEY}
    )
    assert response.status_code == 422


# --- read endpoints ----------------------------------------------------------

def test_health_needs_no_api_key(client):
    body = client.get("/api/honeypot/health").json()
    assert set(body) == {
        "status", "ml_models", "gemini_keys", "gemini_available_keys", "timestamp",
    }
    assert body["status"] == "ok"
    assert body["gemini_keys"] == 0  # keys blanked in tests/conftest.py


def test_unknown_session_is_404(client):
    response = client.get("/api/honeypot/session/nope", headers={"x-api-key": API_KEY})
    assert response.status_code == 404
    assert response.json()["detail"] == "Session not found"


def test_evidence_endpoint_shape(client):
    body = client.get("/api/honeypot/evidence", headers={"x-api-key": API_KEY}).json()
    assert body["status"] == "success"
    assert set(body["data"]) == {"sessions", "masterIntel", "totalScamsDetected"}


def test_config_get_and_post_round_trip(client):
    settings = get_settings()
    original = settings.STRICT_RESPONSE_MODE
    try:
        body = client.post(
            "/api/honeypot/config",
            json={"strictResponseMode": False},
            headers={"x-api-key": API_KEY},
        ).json()
        assert body["settings"]["STRICT_RESPONSE_MODE"] is False

        body = client.get("/api/honeypot/config", headers={"x-api-key": API_KEY}).json()
        assert body["settings"]["STRICT_RESPONSE_MODE"] is False
    finally:
        settings.STRICT_RESPONSE_MODE = original


# --- root --------------------------------------------------------------------

def test_root_returns_the_json_banner(client):
    """DEFECT recorded: main.py registers "/" twice. The first registration
    wins, so the FileResponse handler below it is dead code (fixed in phase 0).
    """
    assert client.get("/").json() == {
        "message": "Quantum Honeypot Active. Go to /dashboard for Command Center."
    }
