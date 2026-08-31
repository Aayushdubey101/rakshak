"""Universal domain schemas.

The contract every later phase depends on. Import from here, not from the
submodules, so the module layout can change without touching call sites.
"""

from packages.shared.schemas.content import (
    IngestionRejection,
    MediaSummary,
    NormalizedContent,
    RejectionReason,
    UrlObservation,
)
from packages.shared.schemas.entities import EntityKind, ExtractedEntity
from packages.shared.schemas.investigation import (
    ContentType,
    InvestigationRequest,
    MediaRef,
    Platform,
    new_investigation_id,
    parse_flexible_timestamp,
    utc_now,
)
from packages.shared.schemas.report import (
    CanonicalReport,
    ModelMetadata,
    Severity,
    StageState,
    StageStatus,
    ThreatIntelMatch,
    UrlFinding,
    Verdict,
)
from packages.shared.schemas.signals import RiskSignal, SignalSource

__all__ = [
    "CanonicalReport",
    "ContentType",
    "EntityKind",
    "ExtractedEntity",
    "IngestionRejection",
    "InvestigationRequest",
    "MediaRef",
    "MediaSummary",
    "NormalizedContent",
    "RejectionReason",
    "UrlObservation",
    "ModelMetadata",
    "Platform",
    "RiskSignal",
    "Severity",
    "SignalSource",
    "StageState",
    "StageStatus",
    "ThreatIntelMatch",
    "UrlFinding",
    "Verdict",
    "new_investigation_id",
    "parse_flexible_timestamp",
    "utc_now",
]
