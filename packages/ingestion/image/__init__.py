"""Screenshot and image text extraction.

Phase 4 originally chose gateway vision alone over pytesseract ("no new
dependency, no new deployment artifact") -- true then, no longer true now
that Phase 10 already carries a CPU-only torch wheel for
packages/ml/text/semantic.py. Local OCR (packages/ml/vision/ocr.py, EasyOCR)
is tried first: fast (well under a second warm), fully offline, never
dependent on an external LLM provider being configured or up. The gateway
vision LLM (Gemini) is the fallback for when local OCR is unavailable or
comes back empty (a low-text/high-context screenshot, or a genuinely blank
image) -- it can read layout/context an OCR pass alone can't, at the cost of
5-15s of thinking-model latency and a live API dependency.

The interface is unchanged: `extract_image_text(bytes) -> summary`.
"""

from __future__ import annotations

import asyncio
import base64
import logging

from packages.ingestion.limits import DEFAULT_LIMITS, IngestionLimits, sniff
from packages.llm.gateway import TaskKind, get_gateway
from packages.ml.vision import ocr as local_ocr
from packages.shared.schemas.content import (
    IngestionRejection,
    MediaSummary,
    RejectionReason,
)
from packages.shared.schemas.investigation import ContentType

logger = logging.getLogger("uvicorn")

VISION_PROMPT = (
    "Transcribe every piece of text visible in this image exactly as it appears, "
    "including sender names, amounts, URLs, UPI IDs, phone numbers, and identifiers. "
    "If the image contains visual fraud indicators (such as fake logos, QR codes, warnings, or lottery certificates) "
    "with little or no text, include a concise factual description of what is shown. "
    "Output the transcribed content directly."
)


async def extract_image_text(
    data: bytes, *, uri: str, limits: IngestionLimits = DEFAULT_LIMITS
) -> MediaSummary | IngestionRejection:
    if len(data) > limits.max_media_bytes:
        return IngestionRejection(
            source=uri,
            reason=RejectionReason.TOO_LARGE,
            detail=f"{len(data)} bytes exceeds {limits.max_media_bytes}",
        )

    mime, kind = sniff(data)
    if kind is not ContentType.IMAGE:
        return IngestionRejection(
            source=uri,
            reason=RejectionReason.UNSUPPORTED_MEDIA,
            detail=f"sniffed {mime or 'unknown'}, not an image",
        )

    summary = MediaSummary(uri=uri, kind=ContentType.IMAGE, mime_type=mime, size_bytes=len(data))

    # Local OCR first -- fast, offline, no LLM dependency. Require at least
    # 10 alphanumeric characters so stray visual noise doesn't short-circuit
    # vision analysis.
    ocr_text = await local_ocr.extract_text(data)
    if ocr_text and sum(c.isalnum() for c in ocr_text) >= 10:
        return summary.model_copy(
            update={"extracted_text": ocr_text[: limits.max_text_chars], "extractor": "local.ocr"}
        )

    gateway = get_gateway()
    if not gateway.has_provider_for(TaskKind.VISION):
        # Degraded, not failed: the image is still evidence, just unread.
        logger.info(f"ℹ️ no vision provider configured; {uri} kept without transcription")
        return summary

    data_url = f"data:{mime};base64,{base64.b64encode(data).decode()}"
    try:
        # Bounded independently of the ingestion StageBudget wrapping this
        # whole function -- a slow/hung vision provider must degrade to
        # "kept, untranscribed" (same as no provider configured), not
        # silently consume the entire ingestion stage.
        text = await asyncio.wait_for(
            gateway.try_generate(TaskKind.VISION, VISION_PROMPT, images=[data_url]), timeout=16.0
        )
    except asyncio.TimeoutError:
        logger.warning(f"⏱️ vision transcription timed out (>16s); {uri} kept without transcription")
        return summary
    if not text:
        return summary

    return summary.model_copy(
        update={
            "extracted_text": text.strip()[: limits.max_text_chars],
            "extractor": "llm.vision",
        }
    )
