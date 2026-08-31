"""End to end: a WhatsApp webhook -> investigate() -> the reply WhatsApp
actually receives is `packages.reports.serializers.to_whatsapp(report)`.

Same scope note as test_telegram_flow.py: test_channel_parity.py already
covers signature/dedup/parity; this is phase 12's own deliverable.
"""

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.reports.serializers import to_whatsapp
from packages.shared.config.settings import get_settings
from packages.shared.dedup import webhook_dedup

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
WHATSAPP_SECRET = "e2e-whatsapp-secret"


@pytest.fixture(autouse=True)
def whatsapp_settings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "WHATSAPP_APP_SECRET", WHATSAPP_SECRET)
    monkeypatch.setattr(settings, "WHATSAPP_ACCESS_TOKEN", "e2e-access")
    monkeypatch.setattr(settings, "WHATSAPP_VERIFY_TOKEN", "e2e-verify")
    monkeypatch.setattr(settings, "WHATSAPP_PHONE_NUMBER_ID", "555000")
    webhook_dedup.clear()
    yield
    webhook_dedup.clear()


@pytest.fixture
def sent(monkeypatch):
    calls = []

    async def _capture(self, conversation_id, text):
        calls.append((conversation_id, text))
        return True

    monkeypatch.setattr("apps.whatsapp_bot.adapter.WhatsAppAdapter.send", _capture)
    return calls


@pytest.fixture
def captured_report(monkeypatch):
    from packages.domain.investigations import orchestrator

    captured = {}
    real = orchestrator.investigate

    async def _recording(request, **kwargs):
        outcome = await real(request, **kwargs)
        captured["report"] = outcome.report
        return outcome

    monkeypatch.setattr("apps.whatsapp_bot.router.investigate", _recording)
    return captured


@pytest.fixture
def client():
    return TestClient(main.app)


def _signed_post(client, payload: dict):
    body = json.dumps(payload).encode()
    signature = hmac.new(WHATSAPP_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        "/webhooks/whatsapp",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": f"sha256={signature}",
        },
    )


def test_the_reply_whatsapp_receives_is_the_shared_serializer_output(client, sent, captured_report):
    payload = {
        "object": "whatsapp_business_account",
        "entry": [{
            "id": "BIZ",
            "changes": [{
                "field": "messages",
                "value": {
                    "metadata": {"phone_number_id": "555000"},
                    "messages": [{
                        "id": "wamid.E2E1",
                        "from": "919876543210",
                        "type": "text",
                        "text": {"body": SCAM_TEXT},
                    }],
                },
            }],
        }],
    }

    response = _signed_post(client, payload)

    assert response.status_code == 200
    assert len(sent) == 1
    conversation_id, text = sent[0]
    assert conversation_id == "919876543210"
    assert text == to_whatsapp(captured_report["report"])
    assert len(text) <= 1600
