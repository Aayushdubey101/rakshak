"""The universal request every channel builds.

Web, WhatsApp, Telegram, and the API all construct an `InvestigationRequest`
and hand it to the same orchestrator. Adapters translate their platform's
payload into this and do nothing else — no detection, no scoring, no AI.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Platform(str, Enum):
    WEB = "web"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    API = "api"


class ContentType(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    PDF = "pdf"
    AUDIO = "audio"
    URL = "url"
    MIXED = "mixed"


def new_investigation_id() -> str:
    """Generated once, at the edge. Carried through every log line, row, and job."""
    return f"inv_{uuid4().hex}"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _from_epoch(seconds: float) -> datetime:
    # >1e12 means it's actually milliseconds since epoch (JS-style) — a real
    # unit mismatch found in historical evidence data, not a hypothetical.
    # Real seconds-since-epoch stays below this for another ~200 years.
    if abs(seconds) > 1e12:
        seconds /= 1000
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def parse_flexible_timestamp(value: Any) -> datetime:
    """Wire formats accept epoch numbers (seconds or, historically,
    milliseconds), numeric strings, and ISO strings. Normalize all of them to
    aware UTC; anything unparseable or out of range falls back to now."""
    if isinstance(value, (int, float)):
        try:
            return _from_epoch(value)
        except (OverflowError, OSError, ValueError):
            return utc_now()
    if isinstance(value, str):
        try:
            return _from_epoch(float(value))
        except (OverflowError, OSError, ValueError):
            pass
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return utc_now()
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return utc_now()


class MediaRef(BaseModel):
    """A pointer to media, never the bytes.

    `uri` is an object-storage key from phase 7 onward; during phase 5 it may be
    a platform media id the adapter can still resolve.
    """

    model_config = ConfigDict(frozen=True)

    kind: ContentType
    uri: str = Field(min_length=1)
    mime_type: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    sha256: str | None = None


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    investigation_id: str = Field(default_factory=new_investigation_id)
    user_id: str | None = None
    platform: Platform
    content_type: ContentType = ContentType.TEXT
    text: str | None = None
    media: tuple[MediaRef, ...] = ()
    urls: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)

    # Consent enforcement (task.md phase 14): "content is not sent to an
    # external provider unless the investigation's consent state permits
    # it." Defaults True -- matching `Investigation.consent_state`'s own
    # "granted" default (phase 7) -- so every existing caller keeps today's
    # behavior; a caller that knows the user withheld consent sets it False
    # and the orchestrator skips the LLM-reasoning half of detection.
    consent_external_processing: bool = True

    @model_validator(mode="after")
    def _require_some_content(self) -> "InvestigationRequest":
        if not (self.text and self.text.strip()) and not self.media and not self.urls:
            raise ValueError("investigation requires text, media, or urls")
        return self
