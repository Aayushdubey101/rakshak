"""Telegram adapter: platform I/O and translation only.

Everything this file knows is Telegram's shape — update envelopes, file ids,
MarkdownV2 escaping. Everything it does not know is deliberate: no detection, no
scoring, no agent. It builds `InvestigationRequest`s and sends text back.
"""

from __future__ import annotations

import hmac
import logging
from typing import Mapping

import httpx

from packages.ingestion.limits import DEFAULT_LIMITS
from packages.reports.serializers import TELEGRAM_MAX_CHARS, escape_markdown_v2, to_telegram
from packages.shared.schemas import ContentType, InvestigationRequest, MediaRef, Platform
from packages.shared.schemas.adapter import WebhookRejected
from packages.shared.schemas.report import CanonicalReport

logger = logging.getLogger("uvicorn")

SECRET_HEADER = "x-telegram-bot-api-secret-token"
MAX_MESSAGE_CHARS = TELEGRAM_MAX_CHARS

__all__ = ["SECRET_HEADER", "MAX_MESSAGE_CHARS", "TelegramAdapter", "escape_markdown_v2"]


class TelegramAdapter:
    name = "telegram"

    def __init__(self, settings):
        self.token = settings.TELEGRAM_BOT_TOKEN
        self.secret = settings.TELEGRAM_WEBHOOK_SECRET
        self.api_base = settings.TELEGRAM_API_BASE.rstrip("/")

    @property
    def is_configured(self) -> bool:
        return bool(self.token and self.secret)

    # -- inbound --------------------------------------------------------------

    def verify_signature(self, headers: Mapping[str, str], body: bytes = b"") -> bool:
        """Telegram signs by echoing a secret we set on setWebhook.

        An unconfigured secret rejects everything: a webhook we cannot
        authenticate is not a webhook we act on.
        """
        if not self.secret:
            logger.error("🔴 TELEGRAM_WEBHOOK_SECRET is unset; rejecting webhook")
            return False
        provided = {k.lower(): v for k, v in headers.items()}.get(SECRET_HEADER, "")
        return hmac.compare_digest(provided, self.secret)

    def parse_webhook(self, payload: dict) -> tuple[InvestigationRequest, ...]:
        message = payload.get("message") or payload.get("channel_post") or {}
        chat_id = str((message.get("chat") or {}).get("id") or "")
        message_id = str(message.get("message_id") or payload.get("update_id") or "")

        if not chat_id:
            return ()

        text = message.get("text") or message.get("caption") or ""
        media: list[MediaRef] = []

        photos = message.get("photo") or []
        if photos:  # Telegram sends every size; the last is the largest
            largest = photos[-1]
            media.append(MediaRef(
                kind=ContentType.IMAGE,
                uri=f"telegram:{largest.get('file_id')}",
                size_bytes=largest.get("file_size"),
            ))

        document = message.get("document") or {}
        if document.get("file_id"):
            mime = document.get("mime_type") or ""
            media.append(MediaRef(
                kind=ContentType.PDF if "pdf" in mime else ContentType.IMAGE,
                uri=f"telegram:{document['file_id']}",
                mime_type=mime or None,
                size_bytes=document.get("file_size"),
            ))

        voice = message.get("voice") or message.get("audio") or {}
        if voice.get("file_id"):
            media.append(MediaRef(
                kind=ContentType.AUDIO,
                uri=f"telegram:{voice['file_id']}",
                mime_type=voice.get("mime_type"),
                size_bytes=voice.get("file_size"),
            ))

        if not text.strip() and not media:
            return ()

        sender = message.get("from") or {}
        content_type = ContentType.TEXT
        if media:
            content_type = ContentType.MIXED if text.strip() else media[0].kind

        return (
            InvestigationRequest(
                platform=Platform.TELEGRAM,
                user_id=str(sender.get("id")) if sender.get("id") else None,
                content_type=content_type,
                text=text or None,
                media=tuple(media),
                metadata={
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "username": sender.get("username"),
                },
            ),
        )

    async def fetch_media(self, ref: MediaRef) -> bytes:
        """`getFile` for the path, then download it, capped at the media limit."""
        if not self.token:
            raise WebhookRejected("telegram token is not configured")

        file_id = ref.uri.removeprefix("telegram:")
        async with httpx.AsyncClient(timeout=DEFAULT_LIMITS.request_timeout_seconds) as client:
            lookup = await client.get(
                f"{self.api_base}/bot{self.token}/getFile", params={"file_id": file_id}
            )
            lookup.raise_for_status()
            file_path = (lookup.json().get("result") or {}).get("file_path")
            if not file_path:
                raise WebhookRejected(f"telegram returned no path for {file_id}")

            download = await client.get(f"{self.api_base}/file/bot{self.token}/{file_path}")
            download.raise_for_status()
            return download.content[: DEFAULT_LIMITS.max_media_bytes]

    # -- outbound -------------------------------------------------------------

    def format_report(self, report: CanonicalReport) -> str:
        """Concise MarkdownV2 -- delegates to `packages.reports.serializers`."""
        return to_telegram(report)

    async def send(self, conversation_id: str, text: str) -> bool:
        if not self.token:
            logger.warning("⚠️ telegram token unset; reply not sent")
            return False
        try:
            async with httpx.AsyncClient(timeout=DEFAULT_LIMITS.request_timeout_seconds) as client:
                response = await client.post(
                    f"{self.api_base}/bot{self.token}/sendMessage",
                    json={
                        "chat_id": conversation_id,
                        "text": text[:MAX_MESSAGE_CHARS],
                        "parse_mode": "MarkdownV2",
                    },
                )
            return response.status_code < 400
        except httpx.HTTPError as exc:
            logger.warning(f"⚠️ telegram send failed: {exc}")
            return False
