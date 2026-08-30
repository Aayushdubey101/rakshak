"""Ingestion: one `InvestigationRequest` in, one `NormalizedContent` out.

Everything downstream — entity extraction, ML, threat intel, the LLM — reads
`NormalizedContent` and never the raw request. That is what lets a channel send
a screenshot, a PDF, or a defanged link and have the pipeline behave the same.

Nothing here raises on bad input. Oversized, unsupported, encrypted, or
SSRF-blocked material becomes a typed rejection carried on the result.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from packages.ingestion.audio import transcribe_audio
from packages.ingestion.image import extract_image_text
from packages.ingestion.limits import DEFAULT_LIMITS, IngestionLimits, sniff
from packages.ingestion.pdf import extract_pdf_text
from packages.ingestion.text import detect_language_of, normalize_text
from packages.ingestion.url import canonicalize, extract_urls, refang, resolve_url
from packages.shared.schemas.content import (
    IngestionRejection,
    MediaSummary,
    NormalizedContent,
    RejectionReason,
    UrlObservation,
)
from packages.shared.schemas.investigation import ContentType, InvestigationRequest, MediaRef

logger = logging.getLogger("uvicorn")

# Resolves a MediaRef to bytes. Phase 7 supplies the object-storage reader; until
# then a caller passes one in, and without it media is recorded but not read.
MediaLoader = Callable[[MediaRef], Awaitable[bytes]]

__all__ = ["MediaLoader", "ingest"]


async def _ingest_media(
    ref: MediaRef, data: bytes, limits: IngestionLimits
) -> MediaSummary | IngestionRejection:
    _, sniffed_kind = sniff(data)
    kind = sniffed_kind or ref.kind  # the bytes win over the declaration

    if kind is ContentType.PDF:
        return extract_pdf_text(data, uri=ref.uri, limits=limits)
    if kind is ContentType.IMAGE:
        return await extract_image_text(data, uri=ref.uri, limits=limits)
    if kind is ContentType.AUDIO:
        return await transcribe_audio(data, uri=ref.uri, limits=limits)

    sniffed = sniffed_kind.value if sniffed_kind else "unknown"
    return IngestionRejection(
        source=ref.uri,
        reason=RejectionReason.UNSUPPORTED_MEDIA,
        detail=f"declared {ref.kind.value}, sniffed {sniffed}",
    )


def _observe_without_resolving(url: str) -> UrlObservation:
    normalized = canonicalize(url)
    return UrlObservation(
        raw=url,
        normalized=normalized,
        host=urlsplit(normalized).hostname or "",
        was_defanged=refang(url) != url,
    )


async def ingest(
    request: InvestigationRequest,
    *,
    limits: IngestionLimits = DEFAULT_LIMITS,
    media_loader: MediaLoader | None = None,
    resolve_urls: bool = False,
) -> NormalizedContent:
    """Normalize text, read attachments, and observe every URL.

    `resolve_urls` is off by default: following a link is an outbound request on
    a stranger's behalf, so it happens only where a caller decided it should
    (the URL-intelligence stage), never as a side effect of parsing a message.
    """
    text = normalize_text(request.text, limits=limits)
    rejections: list[IngestionRejection] = []
    media: list[MediaSummary] = []

    for ref in request.media:
        if media_loader is None:
            if ref.uri.startswith("data:"):
                try:
                    import base64
                    _, b64 = ref.uri.split(",", 1)
                    data = base64.b64decode(b64)
                    outcome = await _ingest_media(ref, data, limits)
                    if isinstance(outcome, IngestionRejection):
                        rejections.append(outcome)
                    else:
                        media.append(outcome)
                    continue
                except Exception as exc:
                    logger.warning(f"⚠️ could not decode inline media data: {exc}")
            media.append(MediaSummary(uri=ref.uri, kind=ref.kind, mime_type=ref.mime_type,
                                      size_bytes=ref.size_bytes))
            continue
        try:
            data = await media_loader(ref)
        except Exception as exc:
            logger.warning(f"⚠️ could not load media {ref.uri}: {exc}")
            rejections.append(IngestionRejection(
                source=ref.uri, reason=RejectionReason.EXTRACTION_FAILED, detail=str(exc)[:200]
            ))
            continue

        outcome = await _ingest_media(ref, data, limits)
        if isinstance(outcome, IngestionRejection):
            rejections.append(outcome)
        else:
            media.append(outcome)

    # URLs come from the request, the message, and anything read out of media.
    haystack = "\n".join([text, *(m.extracted_text for m in media if m.extracted_text)])
    candidates = list(dict.fromkeys([*request.urls, *extract_urls(haystack, limits=limits)]))
    candidates = candidates[: limits.max_urls]

    if resolve_urls and candidates:
        observations = list(
            await asyncio.gather(*(resolve_url(url, limits=limits) for url in candidates))
        )
    else:
        observations = [_observe_without_resolving(url) for url in candidates]

    rejections.extend(
        IngestionRejection(
            source=observation.raw,
            reason=RejectionReason.BLOCKED_TARGET,
            detail=observation.block_reason,
        )
        for observation in observations
        if observation.blocked
    )

    return NormalizedContent(
        investigation_id=request.investigation_id,
        text=text,
        language=detect_language_of(text),
        urls=tuple(observations),
        media=tuple(media),
        rejections=tuple(rejections),
    )
