"""WhatsApp webhook endpoints: Meta's GET challenge and the POST deliveries.

Same shape as Telegram — verify, dedupe, translate, call the shared pipeline,
render, send — because the whole point of the adapter layer is that the two
channels differ only in their I/O.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request, Response

from packages.domain.investigations.orchestrator import investigate
from apps.whatsapp_bot.adapter import WhatsAppAdapter
from packages.shared.config.settings import get_settings
from packages.shared.dedup import webhook_dedup

logger = logging.getLogger("uvicorn")
router = APIRouter(prefix="/webhooks", tags=["whatsapp"])


def get_adapter() -> WhatsAppAdapter:
    return WhatsAppAdapter(get_settings())


@router.get("/whatsapp")
async def whatsapp_challenge(request: Request) -> Response:
    """Meta's subscription handshake: echo hub.challenge if the token matches."""
    adapter = get_adapter()
    params = request.query_params

    if not adapter.verify_challenge(params.get("hub.mode"), params.get("hub.verify_token")):
        logger.warning("🔴 rejected a whatsapp verification challenge")
        return Response(status_code=403)

    return Response(content=params.get("hub.challenge", ""), media_type="text/plain")


@router.post("/whatsapp")
async def whatsapp_webhook(request: Request) -> Response:
    adapter = get_adapter()
    body = await request.body()  # raw bytes: the HMAC is over exactly these

    if not adapter.verify_signature(request.headers, body):
        logger.warning("🔴 rejected an unsigned whatsapp webhook")
        return Response(status_code=403)

    try:
        payload = await request.json()
    except Exception:
        return Response(status_code=400)

    for investigation in adapter.parse_webhook(payload):
        message_id = investigation.metadata.get("message_id", "")
        chat_id = investigation.metadata.get("chat_id", "")

        if message_id and webhook_dedup.seen(adapter.name, message_id):
            logger.info(f"↩️ whatsapp message {message_id} already handled")
            continue

        logger.info(f"📥 [{investigation.investigation_id}] whatsapp message from {chat_id}")

        async def _load(ref, _adapter=adapter):
            return await _adapter.fetch_media(ref)

        outcome = await investigate(investigation, media_loader=_load)
        await adapter.send(chat_id, adapter.format_report(outcome.report))

    # Always 200: Meta retries anything else, for hours.
    return Response(status_code=200)
