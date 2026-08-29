"""Repository interface for the one `CanonicalReport` an investigation
produces. Same boundary as every other `packages/domain/*/repository.py`:
domain code depends on this Protocol, never on an ORM session. The SQLAlchemy
implementation lives in `packages/shared/db/repositories.py`.
"""

from __future__ import annotations

from typing import Optional, Protocol

from packages.shared.schemas.report import CanonicalReport


class ReportRepository(Protocol):
    """`reports.investigation_id` is unique, so `save()` is an upsert:
    replaying the same investigation_id overwrites the row instead of
    accumulating duplicates -- the DB-level expression of "one CanonicalReport
    per investigation, produced once" (task.md phase 12).
    """

    async def save(self, report: CanonicalReport) -> None: ...

    async def get(self, investigation_id: str) -> Optional[CanonicalReport]: ...
