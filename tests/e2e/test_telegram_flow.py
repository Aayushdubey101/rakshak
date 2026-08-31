"""End to end: a Telegram webhook -> investigate() -> the reply Telegram
actually receives is `packages.reports.serializers.to_telegram(report)`.

test_channel_parity.py already proves signature/dedup/parity behavior; this
file is scoped to phase 12's own deliverable -- that the outbound reply is
the shared serializer's output, not an adapter-local copy of it.
"""

import pytest
from fastapi.testclient import TestClient

from apps.api import main
from packages.reports.serializers import to_telegram
from packages.shared.config.settings import get_settings
from packages.shared.dedup import webhook_dedup

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
TELEGRAM_SECRET = "e2e-telegram-secret"


@pytest.fixture(autouse=True)
def telegram_settings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "TELEGRAM_BOT_TOKEN", "e2e:token")
    monkeypatch.setattr(settings, "TELEGRAM_WEBHOOK_SECRET", TELEGRAM_SECRET)
    webhook_dedup.clear()
    yield
    webhook_dedup.clear()


@pytest.fixture
def sent(monkeypatch):
    calls = []

    async def _capture(self, conversation_id, text):
        calls.append((conversation_id, text))
        return True

    monkeypatch.setattr("apps.telegram_bot.adapter.TelegramAdapter.send", _capture)
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

    monkeypatch.setattr("apps.telegram_bot.router.investigate", _recording)
    return captured


@pytest.fixture
def client():
    return TestClient(main.app)


def test_the_reply_telegram_receives_is_the_shared_serializer_output(client, sent, captured_report):
    response = client.post(
        "/webhooks/telegram",
        json={
            "update_id": 1,
            "message": {
                "message_id": 1,
                "chat": {"id": 42},
                "from": {"id": 7, "username": "scammer"},
                "text": SCAM_TEXT,
            },
        },
        headers={"X-Telegram-Bot-Api-Secret-Token": TELEGRAM_SECRET},
    )

    assert response.status_code == 200
    assert len(sent) == 1
    conversation_id, text = sent[0]
    assert conversation_id == "42"
    assert text == to_telegram(captured_report["report"])
    assert len(text) <= 4096
