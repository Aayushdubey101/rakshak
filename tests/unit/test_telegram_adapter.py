"""Phase 5: the Telegram adapter translates and delivers. Nothing else.

Signature verification, update parsing, media fetch, MarkdownV2 rendering. The
absence of detection logic here is the property being protected.
"""

from types import SimpleNamespace

import httpx
import pytest
import respx

from apps.telegram_bot.adapter import SECRET_HEADER, TelegramAdapter, escape_markdown_v2
from packages.shared.schemas import (
    CanonicalReport,
    ContentType,
    MediaRef,
    Platform,
    Severity,
    StageState,
    StageStatus,
    Verdict,
)
from packages.shared.schemas.adapter import PlatformAdapter, WebhookRejected

SECRET = "test-telegram-secret"
TOKEN = "12345:test-token"


def _adapter(**overrides) -> TelegramAdapter:
    settings = SimpleNamespace(
        TELEGRAM_BOT_TOKEN=TOKEN,
        TELEGRAM_WEBHOOK_SECRET=SECRET,
        TELEGRAM_API_BASE="https://api.telegram.test",
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return TelegramAdapter(settings)


def _update(**message) -> dict:
    base = {"message_id": 42, "chat": {"id": 777}, "from": {"id": 999, "username": "scammer"}}
    return {"update_id": 1, "message": {**base, **message}}


def _report(**overrides) -> CanonicalReport:
    base = dict(
        investigation_id="inv_test",
        verdict=Verdict.SCAM,
        risk_score=91,
        severity=Severity.CRITICAL,
        confidence=0.9,
        scam_type="upi_fraud",
    )
    return CanonicalReport(**{**base, **overrides})


def test_adapter_satisfies_the_protocol():
    assert isinstance(_adapter(), PlatformAdapter)


# --- signature ---------------------------------------------------------------

def test_correct_secret_is_accepted():
    assert _adapter().verify_signature({SECRET_HEADER: SECRET}) is True


@pytest.mark.parametrize("headers", [{}, {SECRET_HEADER: "wrong"}, {SECRET_HEADER: ""}])
def test_missing_or_wrong_secret_is_rejected(headers):
    assert _adapter().verify_signature(headers) is False


def test_unconfigured_secret_rejects_everything():
    """No secret means no way to authenticate, so nothing is trusted."""
    adapter = _adapter(TELEGRAM_WEBHOOK_SECRET=None)
    assert adapter.verify_signature({SECRET_HEADER: "anything"}) is False
    assert adapter.is_configured is False


def test_header_lookup_is_case_insensitive():
    assert _adapter().verify_signature({"X-Telegram-Bot-Api-Secret-Token": SECRET}) is True


# --- parsing -----------------------------------------------------------------

def test_text_message_becomes_one_request():
    requests = _adapter().parse_webhook(_update(text="you won 25 lakh"))

    assert len(requests) == 1
    request = requests[0]
    assert request.platform is Platform.TELEGRAM
    assert request.text == "you won 25 lakh"
    assert request.user_id == "999"
    assert request.metadata == {"chat_id": "777", "message_id": "42", "username": "scammer"}
    assert request.content_type is ContentType.TEXT


def test_photo_uses_the_largest_size():
    payload = _update(
        photo=[{"file_id": "small", "file_size": 100}, {"file_id": "large", "file_size": 9000}],
        caption="is this real?",
    )
    request = _adapter().parse_webhook(payload)[0]

    assert request.media[0].uri == "telegram:large"
    assert request.media[0].size_bytes == 9000
    assert request.text == "is this real?"
    assert request.content_type is ContentType.MIXED


def test_pdf_document_is_typed_as_pdf():
    payload = _update(document={"file_id": "doc1", "mime_type": "application/pdf"})
    request = _adapter().parse_webhook(payload)[0]

    assert request.media[0].kind is ContentType.PDF
    assert request.content_type is ContentType.PDF


def test_voice_note_becomes_audio_media():
    payload = _update(voice={"file_id": "v1", "mime_type": "audio/ogg"})
    assert _adapter().parse_webhook(payload)[0].media[0].kind is ContentType.AUDIO


@pytest.mark.parametrize(
    "payload",
    [
        {},                                                 # not a message at all
        {"message": {"message_id": 1}},                     # no chat
        _update(text="   "),                                # nothing to investigate
        {"message": {"chat": {"id": 1}, "message_id": 2}},  # no text, no media
    ],
)
def test_uninvestigable_updates_produce_nothing(payload):
    assert _adapter().parse_webhook(payload) == ()


def test_channel_post_is_handled_like_a_message():
    payload = {"update_id": 5, "channel_post": {"message_id": 9, "chat": {"id": 3}, "text": "hi"}}
    assert _adapter().parse_webhook(payload)[0].text == "hi"


# --- media -------------------------------------------------------------------

@respx.mock
async def test_fetch_media_resolves_then_downloads():
    respx.get(f"https://api.telegram.test/bot{TOKEN}/getFile").mock(
        return_value=httpx.Response(200, json={"result": {"file_path": "photos/a.jpg"}})
    )
    respx.get(f"https://api.telegram.test/file/bot{TOKEN}/photos/a.jpg").mock(
        return_value=httpx.Response(200, content=b"\x89PNG\r\n\x1a\n")
    )

    data = await _adapter().fetch_media(MediaRef(kind=ContentType.IMAGE, uri="telegram:abc"))
    assert data.startswith(b"\x89PNG")


@respx.mock
async def test_fetch_media_without_a_path_is_rejected():
    respx.get(f"https://api.telegram.test/bot{TOKEN}/getFile").mock(
        return_value=httpx.Response(200, json={"result": {}})
    )
    with pytest.raises(WebhookRejected):
        await _adapter().fetch_media(MediaRef(kind=ContentType.IMAGE, uri="telegram:abc"))


async def test_fetch_media_without_a_token_is_rejected():
    with pytest.raises(WebhookRejected):
        await _adapter(TELEGRAM_BOT_TOKEN=None).fetch_media(
            MediaRef(kind=ContentType.IMAGE, uri="telegram:abc")
        )


# --- rendering ---------------------------------------------------------------

def test_markdown_v2_specials_are_escaped():
    assert escape_markdown_v2("pay-now (100%) at a.test!") == r"pay\-now \(100%\) at a\.test\!"


def test_report_rendering_is_short_and_escaped():
    text = _adapter().format_report(_report(red_flags=("urgency", "payment request")))

    assert "Almost certainly a scam" in text
    assert r"Risk: 91/100" in text
    assert "• urgency" in text
    assert len(text) <= 4096


def test_safe_report_does_not_name_a_scam_type():
    text = _adapter().format_report(
        _report(verdict=Verdict.LIKELY_SAFE, risk_score=0, severity=Severity.NONE)
    )
    assert "No scam signals" in text
    assert "Type:" not in text


def test_degraded_report_says_so():
    text = _adapter().format_report(
        _report(stage_status=(StageStatus(stage="ml.text", state=StageState.FAILED),))
    )
    assert "partial analysis" in text


# --- sending -----------------------------------------------------------------

@respx.mock
async def test_send_posts_markdown_v2():
    route = respx.post(f"https://api.telegram.test/bot{TOKEN}/sendMessage").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    assert await _adapter().send("777", "hello") is True
    assert b'"parse_mode":"MarkdownV2"' in route.calls[0].request.read().replace(b" ", b"")


async def test_send_without_a_token_is_a_no_op():
    assert await _adapter(TELEGRAM_BOT_TOKEN=None).send("777", "hello") is False


@respx.mock
async def test_send_failure_is_reported_not_raised():
    respx.post(f"https://api.telegram.test/bot{TOKEN}/sendMessage").mock(
        side_effect=httpx.ConnectError("down")
    )
    assert await _adapter().send("777", "hello") is False
