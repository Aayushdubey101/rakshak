"""WhatsApp adapter (Meta Cloud API): platform I/O and translation only.

Knows envelopes, media ids, HMAC signatures, and the 1600-character reply limit.
Knows nothing about detection — like Telegram, it builds `InvestigationRequest`s
and delivers text.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Mapping

import httpx

from packages.ingestion.limits import DEFAULT_LIMITS
from packages.reports.serializers import WHATSAPP_MAX_CHARS, to_whatsapp
from packages.shared.schemas import ContentType, InvestigationRequest, MediaRef, Platform
from packages.shared.schemas.adapter import WebhookRejected
from packages.shared.schemas.report import CanonicalReport

logger = logging.getLogger("uvicorn")

SIGNATURE_HEADER = "x-hub-signature-256"
MAX_MESSAGE_CHARS = WHATSAPP_MAX_CHARS

_MEDIA_KINDS = {
    "image": ContentType.IMAGE,
    "document": ContentType.PDF,
    "audio": ContentType.AUDIO,
    "voice": ContentType.AUDIO,
    "video": ContentType.AUDIO,
}


class WhatsAppAdapter:
    name = "whatsapp"

    def __init__(self, settings):
        self.app_secret = settings.WHATSAPP_APP_SECRET
        self.access_token = settings.WHATSAPP_ACCESS_TOKEN
        self.verify_token = settings.WHATSAPP_VERIFY_TOKEN
        self.phone_number_id = settings.WHATSAPP_PHONE_NUMBER_ID
        self.graph_base = settings.WHATSAPP_GRAPH_BASE.rstrip("/")

    @property
    def is_configured(self) -> bool:
        return bool(self.app_secret and self.access_token and self.phone_number_id)

    # -- inbound --------------------------------------------------------------

    def verify_challenge(self, mode: str | None, token: str | None) -> bool:
        """Meta's one-time subscription handshake (`GET` with hub.* params)."""
        if not self.verify_token:
            logger.error("🔴 WHATSAPP_VERIFY_TOKEN is unset; rejecting challenge")
            return False
        return mode == "subscribe" and hmac.compare_digest(token or "", self.verify_token)

    def verify_signature(self, headers: Mapping[str, str], body: bytes) -> bool:
        """HMAC-SHA256 of the *raw* body under the app secret.

        Re-serializing parsed JSON would change bytes and break the digest, so
        the router hands the raw body straight through.
        """
        if not self.app_secret:
            logger.error("🔴 WHATSAPP_APP_SECRET is unset; rejecting webhook")
            return False

        provided = {k.lower(): v for k, v in headers.items()}.get(SIGNATURE_HEADER, "")
        if not provided.startswith("sha256="):
            return False

        expected = hmac.new(self.app_secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided.removeprefix("sha256="), expected)

    def parse_webhook(self, payload: dict) -> tuple[InvestigationRequest, ...]:
        requests: list[InvestigationRequest] = []

        for entry in payload.get("entry") or []:
            for change in entry.get("changes") or []:
                value = change.get("value") or {}
                for message in value.get("messages") or []:
                    request = self._parse_message(message, value)
                    if request is not None:
                        requests.append(request)

        return tuple(requests)

    def _parse_message(self, message: dict, value: dict) -> InvestigationRequest | None:
        sender = message.get("from")
        message_id = message.get("id")
        if not sender or not message_id:
            return None

        message_type = message.get("type") or "text"
        text = (message.get("text") or {}).get("body") or ""
        media: list[MediaRef] = []

        kind = _MEDIA_KINDS.get(message_type)
        if kind is not None:
            block = message.get(message_type) or {}
            media_id = block.get("id")
            if media_id:
                mime = block.get("mime_type") or ""
                if message_type == "document" and mime.startswith("image/"):
                    kind = ContentType.IMAGE
                media.append(
                    MediaRef(kind=kind, uri=f"whatsapp:{media_id}", mime_type=mime or None)
                )
                text = text or block.get("caption") or ""

        if not text.strip() and not media:
            return None

        content_type = ContentType.TEXT
        if media:
            content_type = ContentType.MIXED if text.strip() else media[0].kind

        return InvestigationRequest(
            platform=Platform.WHATSAPP,
            user_id=sender,
            content_type=content_type,
            text=text or None,
            media=tuple(media),
            metadata={
                "chat_id": sender,
                "message_id": message_id,
                "phone_number_id": (value.get("metadata") or {}).get("phone_number_id"),
            },
        )

    async def fetch_media(self, ref: MediaRef) -> bytes:
        """Media id → temporary URL → download, capped at the media limit."""
        if not self.access_token:
            raise WebhookRejected("whatsapp access token is not configured")

        media_id = ref.uri.removeprefix("whatsapp:")
        headers = {"Authorization": f"Bearer {self.access_token}"}

        async with httpx.AsyncClient(timeout=DEFAULT_LIMITS.request_timeout_seconds) as client:
            lookup = await client.get(f"{self.graph_base}/{media_id}", headers=headers)
            lookup.raise_for_status()
            url = lookup.json().get("url")
            if not url:
                raise WebhookRejected(f"whatsapp returned no url for {media_id}")

            download = await client.get(url, headers=headers)
            download.raise_for_status()
            return download.content[: DEFAULT_LIMITS.max_media_bytes]

    # -- outbound -------------------------------------------------------------

    def format_report(self, report: CanonicalReport) -> str:
        """Plain text, ≤1600 chars -- delegates to `packages.reports.serializers`."""
        return to_whatsapp(report)

    async def send(self, conversation_id: str, text: str) -> bool:
        if not (self.access_token and self.phone_number_id):
            logger.warning("⚠️ whatsapp credentials unset; reply not sent")
            return False
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_LIMITS.request_timeout_seconds) as client:
                response = await client.post(
                    f"{self.graph_base}/{self.phone_number_id}/messages",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    json={
                        "messaging_product": "whatsapp",
                        "to": conversation_id,
                        "type": "text",
                        "text": {"body": text[:MAX_MESSAGE_CHARS]},
                    },
                )
            return response.status_code < 400
        except httpx.HTTPError as exc:
            logger.warning(f"⚠️ whatsapp send failed: {exc}")
            return False
