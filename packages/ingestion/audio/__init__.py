"""Audio ingestion — interface now, implementation when a channel needs it.

No channel receives voice notes yet. Defining the seam costs nothing and stops
the shape being invented in a hurry when WhatsApp voice arrives; building the
ASR backend before then would be a model dependency nothing calls.

Until a backend is registered, audio is a typed `NOT_IMPLEMENTED` rejection —
the investigation keeps the media as evidence and continues.
"""

from __future__ import annotations

from typing import Protocol

from packages.ingestion.limits import DEFAULT_LIMITS, IngestionLimits, sniff
from packages.shared.schemas.content import (
    IngestionRejection,
    MediaSummary,
    RejectionReason,
)
from packages.shared.schemas.investigation import ContentType


class ASRBackend(Protocol):
    """What an ASR implementation must provide."""

    name: str

    async def transcribe(self, data: bytes, *, mime_type: str | None = None) -> str: ...


_backend: ASRBackend | None = None


def register_backend(backend: ASRBackend | None) -> None:
    """Install the ASR implementation. Called by composition, not by ingesters."""
    global _backend
    _backend = backend


async def transcribe_audio(
    data: bytes, *, uri: str, limits: IngestionLimits = DEFAULT_LIMITS
) -> MediaSummary | IngestionRejection:
    if len(data) > limits.max_media_bytes:
        return IngestionRejection(
            source=uri,
            reason=RejectionReason.TOO_LARGE,
            detail=f"{len(data)} bytes exceeds {limits.max_media_bytes}",
        )

    mime, kind = sniff(data)
    if kind is not ContentType.AUDIO:
        return IngestionRejection(
            source=uri,
            reason=RejectionReason.UNSUPPORTED_MEDIA,
            detail=f"sniffed {mime or 'unknown'}, not audio",
        )

    if _backend is None:
        return IngestionRejection(
            source=uri,
            reason=RejectionReason.NOT_IMPLEMENTED,
            detail="no ASR backend registered",
        )

    text = await _backend.transcribe(data, mime_type=mime)
    return MediaSummary(
        uri=uri,
        kind=ContentType.AUDIO,
        mime_type=mime,
        size_bytes=len(data),
        extracted_text=text.strip()[: limits.max_text_chars],
        extractor=_backend.name,
    )
