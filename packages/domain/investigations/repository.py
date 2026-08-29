"""Repository interfaces. Domain code depends on these, never on an ORM session.

SQLAlchemy implementations live in `packages/shared/db/repositories.py` — the
non-negotiable boundary from `task.md`: "domain code never imports an ORM
session." Anything under `packages/domain` that needs persistence takes one
of these Protocols as a constructor argument, never a session.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Protocol


class EvidenceRepository(Protocol):
    """Replaces `evidence_store.py`'s JSON file. One durable row per honeypot
    session, plus the aggregate views the `/api/honeypot/evidence` endpoint
    has always returned."""

    async def log_session(self, session: dict[str, Any]) -> None: ...

    async def get_evidence(self) -> dict[str, Any]:
        """Returns `{"sessions": {...}, "masterIntel": {...}, "totalScamsDetected": N}`
        — the exact shape `evidence_store.get_evidence()` returned, so the
        `/api/honeypot/evidence` wire contract doesn't change under this swap."""
        ...


class AuditLogRepository(Protocol):
    """Every deletion, purge, and cross-owner access. Nothing about privacy
    is real without this being append-only and always written."""

    async def record(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        reason: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None: ...

    async def list_for_target(self, target_type: str, target_id: str) -> list[dict[str, Any]]: ...


class InvestigationRepository(Protocol):
    """Retention and deletion over the durable investigation records."""

    async def purge_expired(self, *, now: Optional[datetime] = None) -> int:
        """Purges investigations whose `purge_at` has passed. Returns the count."""
        ...

    async def delete_for_owner(self, session_id: str, *, actor: str, reason: str) -> bool:
        """Owner-initiated deletion: removes the investigation, its messages
        and entities, and records the deletion in `audit_logs`. Returns
        whether anything was found to delete."""
        ...

    async def create_pending(self, investigation_id: str, *, platform: str, content_type: str) -> None:
        """Creates the row a report will later attach to (phase 13: the async
        job queue persists a report via a foreign key to this table).
        Idempotent -- a second call for the same id is a no-op."""
        ...

    async def exists(self, investigation_id: str) -> bool:
        """Whether an investigation row has been created -- distinguishes
        "queued, not finished yet" from "never existed" for the poll
        endpoint, independent of whether a report has been written."""
        ...
