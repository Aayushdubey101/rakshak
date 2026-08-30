"""Limits every ingester enforces, and MIME sniffing that ignores the client.

A declared content type is an assertion by whoever sent the file. It is checked
against the actual bytes; when they disagree, the bytes win.
"""

from __future__ import annotations

from dataclasses import dataclass

from packages.shared.schemas.investigation import ContentType

# (magic prefix, mime type, content kind). Ordered, first match wins.
_MAGIC: tuple[tuple[bytes, str, ContentType], ...] = (
    (b"%PDF-", "application/pdf", ContentType.PDF),
    (b"\x89PNG\r\n\x1a\n", "image/png", ContentType.IMAGE),
    (b"\xff\xd8\xff", "image/jpeg", ContentType.IMAGE),
    (b"GIF87a", "image/gif", ContentType.IMAGE),
    (b"GIF89a", "image/gif", ContentType.IMAGE),
    (b"BM", "image/bmp", ContentType.IMAGE),
    (b"ID3", "audio/mpeg", ContentType.AUDIO),
    (b"OggS", "audio/ogg", ContentType.AUDIO),
)


@dataclass(frozen=True)
class IngestionLimits:
    """Hard caps. Exceeding one is a typed rejection, never an exception."""

    max_text_chars: int = 100_000
    max_media_bytes: int = 10 * 1024 * 1024
    max_pdf_pages: int = 50
    max_audio_seconds: int = 600
    max_urls: int = 25
    max_redirects: int = 3
    request_timeout_seconds: float = 5.0
    max_download_bytes: int = 2 * 1024 * 1024


DEFAULT_LIMITS = IngestionLimits()


def sniff(data: bytes) -> tuple[str | None, ContentType | None]:
    """Identify content from its leading bytes. `(mime, kind)`, both None if unknown."""
    for prefix, mime, kind in _MAGIC:
        if data.startswith(prefix):
            return mime, kind
    # RIFF containers carry their real type at offset 8 (WEBP, WAV).
    if data[:4] == b"RIFF" and len(data) >= 12:
        if data[8:12] == b"WEBP":
            return "image/webp", ContentType.IMAGE
        if data[8:12] == b"WAVE":
            return "audio/wav", ContentType.AUDIO
    return None, None
