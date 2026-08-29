"""Data-privacy architecture primitives (phase 7).

Evidence lifecycle, sensitive-field classification, and log redaction.
`Investigation.retention_class` / `.consent_state` / `.left_infrastructure`
(packages/shared/db/models.py) are the per-investigation privacy metadata
this module's states and helpers operate on.

Audited every `logger.*` call under `apps/`, `packages/domain`,
`packages/agents`, `packages/ingestion` while building this (see
work.md's phase 7 notes): none currently logs raw message text or an
extracted entity value — only opaque ids (investigation_id, session_id,
message_id) and canned template strings. `redact_sensitive` exists for the
first call site that changes that, so it doesn't get invented under
pressure later.
"""

from __future__ import annotations

import re
from enum import Enum


class EvidenceState(str, Enum):
    INGESTED = "ingested"
    ANALYZED = "analyzed"
    RETAINED = "retained"
    EXPIRED = "expired"
    PURGED = "purged"


# Every state a given state may move to. Deletion/purge can be reached from
# anywhere; the forward path is otherwise linear.
_TRANSITIONS: dict[EvidenceState, tuple[EvidenceState, ...]] = {
    EvidenceState.INGESTED: (EvidenceState.ANALYZED, EvidenceState.PURGED),
    EvidenceState.ANALYZED: (EvidenceState.RETAINED, EvidenceState.PURGED),
    EvidenceState.RETAINED: (EvidenceState.EXPIRED, EvidenceState.PURGED),
    EvidenceState.EXPIRED: (EvidenceState.PURGED,),
    EvidenceState.PURGED: (),
}


def can_transition(current: EvidenceState, target: EvidenceState) -> bool:
    return target in _TRANSITIONS[current]


# Coarse patterns for log output — not the extraction engine
# (packages/domain/entities/intelligence_extractor.py), which needs to be
# precise. A log line only needs "definitely not the raw value", not a
# structured match.
_UPI_RE = re.compile(r"\b[\w.+-]+@[a-zA-Z]{2,}\b")
_PHONE_RE = re.compile(r"\b\d{10,13}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b")


def redact_sensitive(text: str) -> str:
    """Masks UPI ids, phone numbers, and emails before a value reaches a log
    line. Not applied automatically — call it at the log call site, same as
    every other logging decision in this codebase."""
    text = _EMAIL_RE.sub("[redacted-email]", text)
    text = _UPI_RE.sub("[redacted-upi]", text)
    text = _PHONE_RE.sub("[redacted-phone]", text)
    return text
