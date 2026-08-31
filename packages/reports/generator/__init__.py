"""The seam every serializer renders from.

`packages.domain.investigations.orchestrator` already builds the
`CanonicalReport` exactly once per investigation (`_build_report` plus the
protection stage). This module doesn't rebuild it -- it's the one place
downstream code goes through instead of reaching into
`InvestigationOutcome.report` directly, so nothing downstream can recompute
or duplicate it, and -- when a repository is given -- the one place it is
persisted.

Not wired into a live route yet: `reports.investigation_id` has a foreign key
to `investigations.id`, and nothing on the web/Telegram/WhatsApp request path
creates an `Investigation` row for a per-message investigation_id today (only
the honeypot flow does, keyed by session_id, via `SqlEvidenceRepository`).
Persisting a report there before that gap is closed would violate the FK.
Built and tested against the real repository; see work.md's Phase 12 notes.
"""

from __future__ import annotations

import logging

from packages.domain.reports.repository import ReportRepository
from packages.shared.schemas.report import CanonicalReport

logger = logging.getLogger("uvicorn")

__all__ = ["generate_report", "ReportRepository"]


async def generate_report(
    report: CanonicalReport, *, repository: ReportRepository | None = None
) -> CanonicalReport:
    """Returns the report unchanged. With a repository, persists it too --
    best-effort: a storage failure must not turn a completed investigation
    into an error, same as the orchestrator's own audit-log write."""
    if repository is not None:
        try:
            await repository.save(report)
        except Exception as exc:
            logger.error(f"❌ [{report.investigation_id}] failed to persist report: {exc}")
    return report
