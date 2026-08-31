"""Telegram webhook endpoint.

The handler is deliberately thin: verify, dedupe, translate, call the one shared
pipeline, render, send. Any logic beyond that belongs behind `investigate()`,
not in a channel.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response

from packages.domain.investigations.orchestrator import investigate
from apps.telegram_bot.adapter import TelegramAdapter
from packages.shared.config.settings import get_settings
from packages.shared.dedup import webhook_dedup

logger = logging.getLogger("uvicorn")
router = APIRouter(prefix="/webhooks", tags=["telegram"])


def get_adapter() -> TelegramAdapter:
    return TelegramAdapter(get_settings())


@router.post("/telegram")
async def telegram_webhook(request: Request) -> Response:
    adapter = get_adapter()
    body = await request.body()

    if not adapter.verify_signature(request.headers, body):
        logger.warning("🔴 rejected an unsigned telegram webhook")
        return Response(status_code=403)

    try:
        payload = await request.json()
    except Exception:
        return Response(status_code=400)

    for investigation in adapter.parse_webhook(payload):
        message_id = investigation.metadata.get("message_id", "")
        chat_id = investigation.metadata.get("chat_id", "")

        if message_id and webhook_dedup.seen(adapter.name, message_id):
            logger.info(f"↩️ telegram message {message_id} already handled")
            continue

        logger.info(f"📥 [{investigation.investigation_id}] telegram message from chat {chat_id}")

        async def _load(ref, _adapter=adapter):
            return await _adapter.fetch_media(ref)

        outcome = await investigate(investigation, media_loader=_load)
        await adapter.send(chat_id, adapter.format_report(outcome.report))

    # Always 200: a non-2xx makes Telegram redeliver the same update forever.
    return Response(status_code=200)
