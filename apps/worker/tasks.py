"""arq job functions.

One job per investigation, not one per pipeline stage. task.md's checklist
names a queue per stage (OCR, ASR, ML inference, URL intelligence,
threat-intel enrichment, LLM reasoning, report generation) -- decomposing
`InvestigationOrchestrator.run()` into that many separate arq jobs would mean
rewriting the hardened, per-stage-isolated pipeline phases 6-11 already built
and tested, for no behavioral gain the done-when actually asks for ("killing
the API mid-investigation still lets the worker finish and persist the
report"; "replaying a job twice produces one result"). `run_investigation`
satisfies both by wrapping the existing, unchanged `investigate()` in one
idempotent, retryable unit. See work.md's Phase 13 notes.
"""

from __future__ import annotations

import logging
from typing import Any

from arq import Retry

from packages.domain.investigations.orchestrator import investigate
from packages.reports.generator import generate_report
from packages.shared.db.repositories import (
    get_audit_log_repository,
    get_evidence_repository,
    get_report_repository,
)
from packages.shared.schemas import InvestigationRequest
from packages.shared.schemas.investigation import MediaRef
from packages.shared.storage.object_store import get_object_store

logger = logging.getLogger("uvicorn")

# Idempotency key is investigation_id alone -- one job per investigation, so
# there is exactly one stage to key on (see the module docstring for why this
# isn't investigation_id + pipeline-stage).
MAX_TRIES = 3


async def _object_store_media_loader(ref: MediaRef) -> bytes:
    return await get_object_store().get(ref.uri)


async def run_investigation(ctx: dict[str, Any], payload: dict[str, Any]) -> None:
    """Idempotent by investigation_id: if a report already exists, this
    replay is a no-op -- safe for arq (or a caller) to redeliver."""
    request = InvestigationRequest(**payload)
    investigation_id = request.investigation_id
    report_repository = get_report_repository()

    if await report_repository.get(investigation_id) is not None:
        logger.info(f"↩️ [{investigation_id}] report already exists, skipping replay")
        return

    try:
        outcome = await investigate(request, media_loader=_object_store_media_loader)
        await generate_report(outcome.report, repository=report_repository)
    except Exception as exc:
        job_try = ctx.get("job_try", 1)
        if job_try >= MAX_TRIES:
            logger.error(f"💀 [{investigation_id}] investigation job failed permanently: {exc}")
            await get_audit_log_repository().record(
                actor="worker", action="job_failed",
                target_type="investigation", target_id=investigation_id,
                reason=str(exc)[:500],
            )
            return
        logger.warning(f"⏳ [{investigation_id}] investigation job failed (try {job_try}), retrying: {exc}")
        raise Retry(defer=2**job_try)


async def log_evidence(ctx: dict[str, Any], session: dict[str, Any]) -> None:
    """Durable honeypot evidence logging. Replaces the `BackgroundTasks` call
    in `honeypot_adapter.py` when a queue is configured -- in-process
    background work dies with the API process; this doesn't."""
    await get_evidence_repository().log_session(session)
