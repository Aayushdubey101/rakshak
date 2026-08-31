"""Phase 5's gate: three channels, one investigation result.

A Telegram update, a WhatsApp webhook, and a direct API call carrying the same
message must produce the same report. If an adapter ever grows its own
detection logic, this is the test that fails.
"""

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.shared.config.settings import get_settings
from packages.shared.dedup import webhook_dedup
from packages.shared.schemas import Platform

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
API_KEY = "test_secret_key"
TELEGRAM_SECRET = "parity-telegram-secret"
WHATSAPP_SECRET = "parity-app-secret"

# Fields that legitimately differ between two runs of the same content.
# stage_status: the `agent` stage runs only where an EngagementHook is wired
# (currently just /api/honeypot/); telegram/whatsapp leave it SKIPPED until
# phase 10 wires honeypot engagement into those channels too. That's a scope
# boundary, not adapter-grown detection logic, which is what this test guards.
_VOLATILE = {"investigation_id", "generated_at", "stage_status"}


@pytest.fixture(autouse=True)
def channel_settings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "parity:token")
    monkeypatch.setattr(settings, "TELEGRAM_WEBHOOK_SECRET", TELEGRAM_SECRET)
    monkeypatch.setattr(settings, "WHATSAPP_APP_SECRET", WHATSAPP_SECRET)
    monkeypatch.setattr(settings, "WHATSAPP_ACCESS_TOKEN", "parity-access")
    monkeypatch.setattr(settings, "WHATSAPP_VERIFY_TOKEN", "parity-verify")
    monkeypatch.setattr(settings, "WHATSAPP_PHONE_NUMBER_ID", "555000")
    webhook_dedup.clear()
    yield
    webhook_dedup.clear()


@pytest.fixture
def reports(monkeypatch):
    """Record every report the shared orchestrator produces, on any channel."""
    from packages.domain.investigations import orchestrator

    recorded = []
    real = orchestrator.investigate

    async def _recording(request, **kwargs):
        outcome = await real(request, **kwargs)
        recorded.append((request.platform, outcome.report))
        return outcome

    for module in (
        "apps.api.routers.investigations",
        "apps.api.honeypot_adapter",
        "apps.telegram_bot.router",
        "apps.whatsapp_bot.router",
    ):
        monkeypatch.setattr(f"{module}.investigate", _recording)
    return recorded


@pytest.fixture
def client(monkeypatch):
    """No outbound replies: adapters are exercised, the platforms are not called."""
    async def _no_send(self, conversation_id, text):
        return True

    monkeypatch.setattr("apps.telegram_bot.adapter.TelegramAdapter.send", _no_send)
    monkeypatch.setattr("apps.whatsapp_bot.adapter.WhatsAppAdapter.send", _no_send)
    return TestClient(main.app)


def _comparable(report) -> dict:
    return report.model_dump(exclude=_VOLATILE)


def _telegram_update(text: str = SCAM_TEXT, message_id: int = 5001) -> dict:
    return {
        "update_id": 900,
        "message": {
            "message_id": message_id,
            "chat": {"id": 777},
            "from": {"id": 999, "username": "scammer"},
            "text": text,
        },
    }


def _whatsapp_payload(text: str = SCAM_TEXT, message_id: str = "wamid.PARITY1") -> dict:
    return {
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "BIZ",
            "changes": [{
                "field": "messages",
                "value": {
                    "metadata": {"phone_number_id": "555000"},
                    "messages": [{
                        "id": message_id,
                        "from": "919876543210",
                        "type": "text",
                        "text": {"body": text},
                    }],
                },
            }],
        }],
    }


def _post_telegram(client, payload: dict, secret: str = TELEGRAM_SECRET):
    return client.post(
        "/webhooks/telegram",
        json=payload,
        headers={"X-Telegram-Bot-Api-Secret-Token": secret},
    )


def _post_whatsapp(client, payload: dict, secret: str = WHATSAPP_SECRET):
    body = json.dumps(payload).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        "/webhooks/whatsapp",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": f"sha256={signature}",
        },
    )


def _post_api(client, text: str = SCAM_TEXT, session_id: str = "parity-web"):
    return client.post(
        "/api/honeypot/",
        json={"sessionId": session_id, "message": {"sender": "scammer", "text": text}},
        headers={"x-api-key": API_KEY},
    )


# --- the gate ----------------------------------------------------------------

def test_all_three_channels_produce_the_same_report(client, reports):
    assert _post_telegram(client, _telegram_update()).status_code == 200
    assert _post_whatsapp(client, _whatsapp_payload()).status_code == 200
    assert _post_api(client).status_code == 200

    assert [platform for platform, _ in reports] == [
        Platform.TELEGRAM, Platform.WHATSAPP, Platform.API
    ]

    telegram, whatsapp, web = (_comparable(report) for _, report in reports)
    assert telegram == whatsapp == web
    assert telegram["verdict"] == "scam"
    assert telegram["risk_score"] > 0
    assert any(
        e["kind"] == "upi_id" and e["value"] == "scammer@okaxis"
        for e in telegram["extracted_entities"]
    )


def test_each_channel_gets_its_own_investigation_id(client, reports):
    _post_telegram(client, _telegram_update())
    _post_whatsapp(client, _whatsapp_payload())

    assert len({report.investigation_id for _, report in reports}) == 2


# --- signature enforcement at the edge ---------------------------------------

@pytest.mark.parametrize("headers", [{}, {"X-Telegram-Bot-Api-Secret-Token": "wrong"}])
def test_unsigned_telegram_webhooks_never_reach_the_pipeline(client, reports, headers):
    response = client.post("/webhooks/telegram", json=_telegram_update(), headers=headers)

    assert response.status_code == 403
    assert reports == []


def test_tampered_whatsapp_body_never_reaches_the_pipeline(client, reports):
    response = _post_whatsapp(client, _whatsapp_payload(), secret="not-the-app-secret")

    assert response.status_code == 403
    assert reports == []


def test_whatsapp_verification_challenge_is_echoed(client):
    response = client.get(
        "/webhooks/whatsapp",
        params={
            "hub.mode": "subscribe",
            "hub.verify_token": "parity-verify",
            "hub.challenge": "1234567",
        },
    )
    assert (response.status_code, response.text) == (200, "1234567")


def test_whatsapp_challenge_with_a_wrong_token_is_refused(client):
    response = client.get(
        "/webhooks/whatsapp",
        params={"hub.mode": "subscribe", "hub.verify_token": "nope", "hub.challenge": "1"},
    )
    assert response.status_code == 403


# --- retries -----------------------------------------------------------------

def test_a_redelivered_telegram_update_is_investigated_once(client, reports):
    payload = _telegram_update(message_id=6001)

    assert _post_telegram(client, payload).status_code == 200
    assert _post_telegram(client, payload).status_code == 200  # platform retry

    assert len(reports) == 1


def test_a_redelivered_whatsapp_message_is_investigated_once(client, reports):
    payload = _whatsapp_payload(message_id="wamid.RETRY")

    assert _post_whatsapp(client, payload).status_code == 200
    assert _post_whatsapp(client, payload).status_code == 200

    assert len(reports) == 1


def test_a_webhook_with_nothing_to_investigate_is_accepted_quietly(client, reports):
    response = client.post(
        "/webhooks/telegram",
        json={"update_id": 1, "message": {"message_id": 1, "chat": {"id": 2}}},
        headers={"X-Telegram-Bot-Api-Secret-Token": TELEGRAM_SECRET},
    )

    assert response.status_code == 200  # 200 or the platform retries forever
    assert reports == []
