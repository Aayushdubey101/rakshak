"""The one report an investigation produces.

Every investigation produces exactly one `CanonicalReport`. Channels render it
differently; they never compute a different one. `stage_status` is what makes a
partial pipeline honest: a failed stage degrades the report instead of aborting
the investigation or silently reporting a clean verdict.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from packages.shared.schemas.entities import EntityKind, ExtractedEntity
from packages.shared.schemas.investigation import utc_now


class Verdict(str, Enum):
    SCAM = "scam"
    SUSPICIOUS = "suspicious"
    LIKELY_SAFE = "likely_safe"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StageState(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"
    SKIPPED = "skipped"


class StageStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    stage: str = Field(min_length=1, description="e.g. 'ingestion', 'ml.text', 'llm'")
    state: StageState
    error: str | None = None
    duration_ms: int | None = Field(default=None, ge=0)


class UrlFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1)
    normalized_url: str | None = None
    verdict: Verdict = Verdict.UNKNOWN
    reasons: tuple[str, ...] = ()
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class ThreatIntelMatch(BaseModel):
    """Why we believe this content resembles something we have seen before."""

    model_config = ConfigDict(frozen=True)

    indicator: str = Field(min_length=1)
    kind: EntityKind
    source: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime | None = None
    campaign_id: str | None = None


class ModelMetadata(BaseModel):
    """Which model answered for which stage. Written for every inference."""

    model_config = ConfigDict(frozen=True, protected_namespaces=())

    stage: str = Field(min_length=1)
    provider: str | None = None
    model_id: str | None = None
    version: str | None = None
    latency_ms: int | None = Field(default=None, ge=0)


class CanonicalReport(BaseModel):
    model_config = ConfigDict(frozen=True, protected_namespaces=())

    investigation_id: str = Field(min_length=1)
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    scam_type: str | None = None
    explanation: str | None = Field(
        default=None, description="Plain-language finding, from packages.agents.protection"
    )
    red_flags: tuple[str, ...] = ()
    extracted_entities: tuple[ExtractedEntity, ...] = ()
    url_findings: tuple[UrlFinding, ...] = ()
    threat_intel: tuple[ThreatIntelMatch, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = Field(
        default=(), description="Object-storage keys; never inline blobs"
    )
    model_metadata: tuple[ModelMetadata, ...] = ()
    stage_status: tuple[StageStatus, ...] = ()
    generated_at: datetime = Field(default_factory=utc_now)

    @property
    def is_degraded(self) -> bool:
        return any(s.state in (StageState.DEGRADED, StageState.FAILED) for s in self.stage_status)

    def entities_of(self, kind: EntityKind) -> tuple[ExtractedEntity, ...]:
        return tuple(entity for entity in self.extracted_entities if entity.kind is kind)
