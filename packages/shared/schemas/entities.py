"""Entities extracted from investigated content.

Replaces the five bare `list[str]` buckets (`upiIds`, `phoneNumbers`,
`bankAccounts`, `phishingLinks`, `suspiciousKeywords`) with one typed shape, so
every producer — regex, NER, vision OCR, threat intel — emits the same thing.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class EntityKind(str, Enum):
    UPI_ID = "upi_id"
    PHONE = "phone"
    BANK_ACCOUNT = "bank_account"
    URL = "url"
    DOMAIN = "domain"
    EMAIL = "email"
    KEYWORD = "keyword"
    ORGANIZATION = "organization"
    PERSON = "person"
    AMOUNT = "amount"


class ExtractedEntity(BaseModel):
    """One entity, with the confidence and the component that produced it.

    `normalized_value` is the comparable form used for correlation and hashing
    (phase 9): a phone number without its country prefix, a URL without its
    tracking parameters. It defaults to `value` when no normalization applies.
    """

    model_config = ConfigDict(frozen=True)

    kind: EntityKind
    value: str = Field(min_length=1)
    normalized_value: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1, description="Producing component, e.g. 'regex.upi'")

    @property
    def comparable(self) -> str:
        return self.normalized_value or self.value
