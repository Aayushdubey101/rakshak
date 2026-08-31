"""Phase 5: the WhatsApp adapter translates and delivers. Nothing else.

The signature is an HMAC over the raw body, so the property that matters most
here is that a tampered or unsigned body never reaches the pipeline.
"""

import hashlib
import hmac
import json
from types import SimpleNamespace

import httpx
import pytest
import respx

from apps.whatsapp_bot.adapter import SIGNATURE_HEADER, WhatsAppAdapter
from packages.shared.schemas import (
    CanonicalReport,
    ContentType,
    MediaRef,
    Platform,
    Severity,
    Verdict,
)
from packages.shared.schemas.adapter import PlatformAdapter, WebhookRejected

APP_SECRET = "test-app-secret"
ACCESS_TOKEN = "test-access-token"
VERIFY_TOKEN = "test-verify-token"
PHONE_ID = "555000"


def _adapter(**overrides) -> WhatsAppAdapter:
    settings = SimpleNamespace(
        WHATSAPP_APP_SECRET=APP_SECRET,
        WHATSAPP_ACCESS_TOKEN=ACCESS_TOKEN,
        WHATSAPP_VERIFY_TOKEN=VERIFY_TOKEN,
        WHATSAPP_PHONE_NUMBER_ID=PHONE_ID,
        WHATSAPP_GRAPH_BASE="https://graph.test/v21.0",
    )
    for key, value in overrides.items():
        setattr(settings, key, value)
    return WhatsAppAdapter(settings)


def sign(body: bytes, secret: str = APP_SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _webhook(*messages: dict) -> dict:
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "BIZ",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "metadata": {"phone_number_id": PHONE_ID},
                            "messages": list(messages),
                        },
                    }
                ],
            }
        ],
    }


def _text_message(body: str = "you won 25 lakh", **overrides) -> dict:
    return {
        "id": "wamid.TEST1",
        "from": "919876543210",
        "type": "text",
        "text": {"body": body},
        **overrides,
    }


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


# --- verification challenge --------------------------------------------------

def test_challenge_accepts_the_configured_token():
    assert _adapter().verify_challenge("subscribe", VERIFY_TOKEN) is True


@pytest.mark.parametrize(
    "mode,token", [("subscribe", "wrong"), ("unsubscribe", VERIFY_TOKEN), (None, None)]
)
def test_challenge_rejects_everything_else(mode, token):
    assert _adapter().verify_challenge(mode, token) is False


def test_challenge_without_a_configured_token_is_refused():
    assert _adapter(WHATSAPP_VERIFY_TOKEN=None).verify_challenge("subscribe", "x") is False


# --- signature ---------------------------------------------------------------

def test_correct_hmac_is_accepted():
    body = json.dumps(_webhook(_text_message())).encode()
    assert _adapter().verify_signature({SIGNATURE_HEADER: sign(body)}, body) is True


def test_tampered_body_is_rejected():
    body = json.dumps(_webhook(_text_message())).encode()
    assert _adapter().verify_signature({SIGNATURE_HEADER: sign(body)}, body + b" ") is False


def test_signature_from_the_wrong_secret_is_rejected():
    body = b'{"entry":[]}'
    assert _adapter().verify_signature({SIGNATURE_HEADER: sign(body, "other")}, body) is False


@pytest.mark.parametrize(
    "headers", [{}, {SIGNATURE_HEADER: "deadbeef"}, {SIGNATURE_HEADER: "sha1=abc"}]
)
def test_missing_or_malformed_signature_is_rejected(headers):
    assert _adapter().verify_signature(headers, b"{}") is False


def test_unconfigured_secret_rejects_everything():
    body = b"{}"
    adapter = _adapter(WHATSAPP_APP_SECRET=None)
    assert adapter.verify_signature({SIGNATURE_HEADER: sign(body)}, body) is False
    assert adapter.is_configured is False


# --- parsing -----------------------------------------------------------------

def test_text_message_becomes_one_request():
    request = _adapter().parse_webhook(_webhook(_text_message()))[0]

    assert request.platform is Platform.WHATSAPP
    assert request.text == "you won 25 lakh"
    assert request.user_id == "919876543210"
    assert request.metadata["message_id"] == "wamid.TEST1"
    assert request.metadata["phone_number_id"] == PHONE_ID


def test_several_messages_become_several_requests():
    payload = _webhook(_text_message("first"), _text_message("second", id="wamid.TEST2"))
    assert [r.text for r in _adapter().parse_webhook(payload)] == ["first", "second"]


def test_image_message_carries_a_media_ref():
    message = {
        "id": "wamid.IMG",
        "from": "919876543210",
        "type": "image",
        "image": {"id": "media-1", "mime_type": "image/jpeg", "caption": "look"},
    }
    request = _adapter().parse_webhook(_webhook(message))[0]

    assert request.media[0].uri == "whatsapp:media-1"
    assert request.media[0].kind is ContentType.IMAGE
    assert request.text == "look"
    assert request.content_type is ContentType.MIXED


def test_pdf_document_is_typed_as_pdf():
    message = {
        "id": "wamid.DOC",
        "from": "919876543210",
        "type": "document",
        "document": {"id": "media-2", "mime_type": "application/pdf"},
    }
    request = _adapter().parse_webhook(_webhook(message))[0]
    assert request.media[0].kind is ContentType.PDF
    assert request.content_type is ContentType.PDF


def test_image_sent_as_a_document_is_still_an_image():
    message = {
        "id": "wamid.DOC2",
        "from": "919876543210",
        "type": "document",
        "document": {"id": "media-3", "mime_type": "image/png"},
    }
    assert _adapter().parse_webhook(_webhook(message))[0].media[0].kind is ContentType.IMAGE


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"entry": []},
        _webhook({"id": "x", "type": "text", "text": {"body": "hi"}}),              # no sender
        _webhook({"from": "919876543210", "type": "text", "text": {"body": ""}}),   # no id or body
        {"entry": [{"changes": [{"value": {"statuses": [{"status": "read"}]}}]}]},  # receipt
    ],
)
def test_uninvestigable_payloads_produce_nothing(payload):
    assert _adapter().parse_webhook(payload) == ()


# --- media -------------------------------------------------------------------

@respx.mock
async def test_fetch_media_resolves_then_downloads():
    respx.get("https://graph.test/v21.0/media-1").mock(
        return_value=httpx.Response(200, json={"url": "https://lookaside.test/blob"})
    )
    route = respx.get("https://lookaside.test/blob").mock(
        return_value=httpx.Response(200, content=b"\x89PNG\r\n\x1a\n")
    )

    data = await _adapter().fetch_media(MediaRef(kind=ContentType.IMAGE, uri="whatsapp:media-1"))

    assert data.startswith(b"\x89PNG")
    assert route.calls[0].request.headers["Authorization"] == f"Bearer {ACCESS_TOKEN}"


@respx.mock
async def test_fetch_media_without_a_url_is_rejected():
    respx.get("https://graph.test/v21.0/media-1").mock(return_value=httpx.Response(200, json={}))
    with pytest.raises(WebhookRejected):
        await _adapter().fetch_media(MediaRef(kind=ContentType.IMAGE, uri="whatsapp:media-1"))


async def test_fetch_media_without_a_token_is_rejected():
    with pytest.raises(WebhookRejected):
        await _adapter(WHATSAPP_ACCESS_TOKEN=None).fetch_media(
            MediaRef(kind=ContentType.IMAGE, uri="whatsapp:media-1")
        )


# --- rendering ---------------------------------------------------------------

def test_report_is_plain_text_within_the_limit():
    text = _adapter().format_report(_report(red_flags=tuple(f"flag {i}" for i in range(20))))

    assert "Almost certainly a scam" in text
    assert "Risk: 91/100" in text
    assert "\\" not in text            # no markdown escaping on this channel
    assert len(text) <= 1600
    assert text.count("- flag") == 5   # capped at five


# --- sending -----------------------------------------------------------------

@respx.mock
async def test_send_posts_to_the_messages_endpoint():
    route = respx.post(f"https://graph.test/v21.0/{PHONE_ID}/messages").mock(
        return_value=httpx.Response(200, json={"messages": [{"id": "wamid.OUT"}]})
    )

    assert await _adapter().send("919876543210", "hello") is True
    body = json.loads(route.calls[0].request.read())
    assert body["messaging_product"] == "whatsapp"
    assert body["text"]["body"] == "hello"


async def test_send_without_credentials_is_a_no_op():
    assert await _adapter(WHATSAPP_ACCESS_TOKEN=None).send("919876543210", "hi") is False


@respx.mock
async def test_send_failure_is_reported_not_raised():
    respx.post(f"https://graph.test/v21.0/{PHONE_ID}/messages").mock(
        side_effect=httpx.ConnectError("down")
    )
    assert await _adapter().send("919876543210", "hi") is False
