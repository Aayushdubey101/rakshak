"""What ingestion hands to the rest of the pipeline.

Ingestion turns whatever a channel received — text, a URL, a screenshot, a PDF —
into one `NormalizedContent`. Anything it refuses becomes a typed
`IngestionRejection` carried alongside the content, never a raw exception: an
oversized attachment degrades an investigation, it does not fail one.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from packages.shared.schemas.investigation import ContentType


class RejectionReason(str, Enum):
    TOO_LARGE = "too_large"
    TOO_MANY_PAGES = "too_many_pages"
    TOO_LONG = "too_long"
    UNSUPPORTED_MEDIA = "unsupported_media"
    ENCRYPTED = "encrypted"
    BLOCKED_TARGET = "blocked_target"      # SSRF guard refused the destination
    TIMEOUT = "timeout"
    EXTRACTION_FAILED = "extraction_failed"
    NOT_IMPLEMENTED = "not_implemented"    # declared interface, deferred build


class IngestionRejection(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str = Field(min_length=1, description="What was refused, e.g. a URL or media uri")
    reason: RejectionReason
    detail: str | None = None


class UrlObservation(BaseModel):
    """One URL as found, as normalized, and as far as we were willing to follow it."""

    model_config = ConfigDict(frozen=True)

    raw: str = Field(min_length=1)
    normalized: str = Field(min_length=1)
    host: str = ""
    was_defanged: bool = False
    blocked: bool = False
    block_reason: str | None = None
    final_url: str | None = None
    redirect_chain: tuple[str, ...] = ()
    status_code: int | None = None


class MediaSummary(BaseModel):
    """What we managed to read out of one attachment."""

    model_config = ConfigDict(frozen=True)

    uri: str = Field(min_length=1)
    kind: ContentType
    mime_type: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    pages: int | None = Field(default=None, ge=0)
    extracted_text: str = ""
    extractor: str | None = Field(default=None, description="e.g. 'pypdf', 'llm.vision'")


class NormalizedContent(BaseModel):
    model_config = ConfigDict(frozen=True)

    investigation_id: str = Field(min_length=1)
    text: str = ""
    language: str = "en"
    urls: tuple[UrlObservation, ...] = ()
    media: tuple[MediaSummary, ...] = ()
    rejections: tuple[IngestionRejection, ...] = ()

    @property
    def analyzable_text(self) -> str:
        """Message text, anything read out of attachments, and raw URL strings.
        A link-only submission (content_type=url, no message text) otherwise
        gives detector.analyze() an empty string to work with -- nothing for
        keyword/behavioral signals to see even when the URL itself contains
        obvious red flags ("bank-alert...verify?id=...")."""
        parts = [
            self.text,
            *(m.extracted_text for m in self.media if m.extracted_text),
            *(u.raw for u in self.urls),
        ]
        return "\n\n".join(part for part in parts if part.strip())

    @property
    def blocked_urls(self) -> tuple[UrlObservation, ...]:
        return tuple(url for url in self.urls if url.blocked)
