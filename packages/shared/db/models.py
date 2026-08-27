"""The 14 tables phase 7 introduces, replacing JSON-file + in-memory state.

Structured data lives here; embeddings in pgvector (`scam_campaigns.embedding`);
blobs never land in a column — `attachments.object_key` points at object
storage (phase 7's storage-boundaries rule).

`scam_campaigns.embedding` uses `Vector` on Postgres and falls back to `JSON`
on sqlite (`.with_variant`) — pgvector similarity search is phase 9's job:
the column exists now so the schema doesn't change under it later, but
nothing here exercises vector search, so the offline test suite doesn't need
a real pgvector install.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, String, Text, Boolean
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

try:
    from pgvector.sqlalchemy import Vector
except ImportError:  # pragma: no cover
    Vector = None


def _uuid() -> str:
    return uuid.uuid4().hex


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _embedding_column(dim: int):
    if Vector is None:
        return mapped_column(JSON, nullable=True)
    return mapped_column(Vector(dim).with_variant(JSON(), "sqlite"), nullable=True)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), unique=True, nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    retention_class: Mapped[str] = mapped_column(String(32), default="standard")
    consent_state: Mapped[str] = mapped_column(String(32), default="granted")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class PlatformAccount(Base):
    __tablename__ = "platform_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    platform: Mapped[str] = mapped_column(String(32))
    platform_account_id: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    __table_args__ = (Index("ix_platform_account_lookup", "platform", "platform_account_id"),)


class Investigation(Base):
    __tablename__ = "investigations"

    # Matches new_investigation_id() -> "inv_<uuid4hex>", not a fresh uuid.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id"), nullable=True)
    platform_account_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("platform_accounts.id"), nullable=True
    )
    platform: Mapped[str] = mapped_column(String(32))
    content_type: Mapped[str] = mapped_column(String(32))
    verdict: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    scam_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_degraded: Mapped[bool] = mapped_column(Boolean, default=False)

    # Isolation (phase 11): "consumer" (default — a protection/investigation
    # request) or "honeypot_research" (a researcher-authorized engagement).
    # Same physical table, not a new one — task.md's phase 7 fixed the table
    # list — but every honeypot-writing query tags this, and evidence queries
    # filter by it, so the two never mix by accident.
    data_origin: Mapped[str] = mapped_column(String(16), default="consumer", index=True)

    # Data-privacy architecture (phase 7).
    retention_class: Mapped[str] = mapped_column(String(32), default="standard")
    consent_state: Mapped[str] = mapped_column(String(32), default="granted")
    left_infrastructure: Mapped[bool] = mapped_column(
        Boolean, default=False, doc="True if any provider processed content externally."
    )
    evidence_state: Mapped[str] = mapped_column(String(16), default="ingested")
    purge_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    messages: Mapped[list["Message"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    attachments: Mapped[list["Attachment"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    entities: Mapped[list["Entity"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    urls: Mapped[list["Url"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    sender: Mapped[str] = mapped_column(String(32))
    text: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    investigation: Mapped[Investigation] = relationship(back_populates="messages")


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    kind: Mapped[str] = mapped_column(String(32))
    object_key: Mapped[str] = mapped_column(String(512), doc="Object-storage key; never a blob.")
    content_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    extracted_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    investigation: Mapped[Investigation] = relationship(back_populates="attachments")


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    kind: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(512))
    normalized_value: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    investigation: Mapped[Investigation] = relationship(back_populates="entities")


class Url(Base):
    __tablename__ = "urls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    raw: Mapped[str] = mapped_column(Text)
    normalized: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    block_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    investigation: Mapped[Investigation] = relationship(back_populates="urls")


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    reputation_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)


class RiskAssessment(Base):
    """One row per `RiskSignal` (packages/shared/schemas/signals.py) produced."""

    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    source: Mapped[str] = mapped_column(String(32))
    score: Mapped[float] = mapped_column(Float)
    label: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    model_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class ScamClassification(Base):
    __tablename__ = "scam_classifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    scam_type: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    method: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"), unique=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, doc="CanonicalReport.model_dump()")
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    kind: Mapped[str] = mapped_column(String(32))
    value_hash: Mapped[str] = mapped_column(String(128), doc="Normalized indicator, hashed.")
    campaign_id: Mapped[Optional[str]] = mapped_column(ForeignKey("scam_campaigns.id"), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    __table_args__ = (Index("ix_threat_indicator_lookup", "kind", "value_hash"),)


class ScamCampaign(Base):
    __tablename__ = "scam_campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    embedding: Mapped[Optional[Any]] = _embedding_column(1536)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class ModelRun(Base):
    __tablename__ = "model_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id"))
    stage: Mapped[str] = mapped_column(String(32))
    model_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)


class ApiKey(Base):
    """Real scoped credentials (phase 14), replacing the single shared
    `API_SECRET_KEY`. Only `key_hash` (sha256 of the plaintext token) is
    stored -- the plaintext is shown once, at creation, and never again."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    principal: Mapped[str] = mapped_column(String(128))
    scopes: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    """Every deletion, purge, and cross-owner access lands here (phase 7 privacy model)."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(32))
    target_id: Mapped[str] = mapped_column(String(64))
    reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    audit_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)
