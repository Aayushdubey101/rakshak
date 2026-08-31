"""apps/worker/tasks.py -- phase 13's job functions, against the real
repositories (this directory's `isolated_database` fixture, same pattern as
test_report_repository.py).

`test_run_investigation_persists_a_report` and
`test_run_investigation_is_idempotent_on_replay` are the automated proxies
for task.md's done-when: the job function completes and persists a report
with no API request in the call stack at all (proving durability doesn't
depend on the API process being alive), and a replayed job produces exactly
one investigate() call / one report.
"""

import pytest
from arq import Retry
from sqlalchemy import select

from apps.worker import tasks as worker_tasks
from apps.worker.tasks import MAX_TRIES, log_evidence, run_investigation
from packages.shared.db.engine import get_session_factory
from packages.shared.db.models import AuditLog, Investigation
from packages.shared.db.repositories import get_evidence_repository, get_report_repository

SCAM_TEXT = "Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."


async def _seed_investigation(investigation_id: str) -> None:
    async with get_session_factory()() as db:
        db.add(Investigation(id=investigation_id, platform="web", content_type="text"))
        await db.commit()


def _payload(investigation_id: str, text: str = SCAM_TEXT) -> dict:
    return {"investigation_id": investigation_id, "platform": "web", "content_type": "text", "text": text}


async def test_run_investigation_persists_a_report():
    await _seed_investigation("inv_worker_1")

    await run_investigation({"job_try": 1}, _payload("inv_worker_1"))

    report = await get_report_repository().get("inv_worker_1")
    assert report is not None
    assert report.verdict.value == "scam"


async def test_run_investigation_is_idempotent_on_replay(monkeypatch):
    await _seed_investigation("inv_worker_2")
    calls = []
    real_investigate = worker_tasks.investigate

    async def _counting(request, **kwargs):
        calls.append(request.investigation_id)
        return await real_investigate(request, **kwargs)

    monkeypatch.setattr(worker_tasks, "investigate", _counting)
    payload = _payload("inv_worker_2")

    await run_investigation({"job_try": 1}, payload)
    await run_investigation({"job_try": 1}, payload)

    assert len(calls) == 1


async def test_run_investigation_retries_with_backoff_below_max_tries(monkeypatch):
    await _seed_investigation("inv_worker_3")

    async def _boom(request, **kwargs):
        raise RuntimeError("provider down")

    monkeypatch.setattr(worker_tasks, "investigate", _boom)

    with pytest.raises(Retry) as exc_info:
        await run_investigation({"job_try": 1}, _payload("inv_worker_3"))

    assert exc_info.value.defer_score == 2 * 1000  # 2**1 seconds, in ms
    assert await get_report_repository().get("inv_worker_3") is None


async def test_run_investigation_dead_letters_after_max_tries(monkeypatch):
    await _seed_investigation("inv_worker_4")

    async def _boom(request, **kwargs):
        raise RuntimeError("provider down")

    monkeypatch.setattr(worker_tasks, "investigate", _boom)

    await run_investigation({"job_try": MAX_TRIES}, _payload("inv_worker_4"))  # must not raise

    async with get_session_factory()() as db:
        rows = (await db.scalars(
            select(AuditLog).where(AuditLog.target_id == "inv_worker_4", AuditLog.action == "job_failed")
        )).all()
    assert len(rows) == 1
    assert "provider down" in rows[0].reason


async def test_log_evidence_persists_the_session():
    session = {
        "sessionId": "worker-session-1",
        "scamDetected": True,
        "scamType": "upi_fraud",
        "messageCount": 2,
        "extractedIntelligence": {
            "upiIds": ["scammer@okaxis"], "phoneNumbers": [], "bankAccounts": [],
            "phishingLinks": [], "suspiciousKeywords": [],
        },
        "conversationHistory": [],
        "startTime": 0,
    }

    await log_evidence({}, session)

    evidence = await get_evidence_repository().get_evidence()
    assert "worker-session-1" in evidence["sessions"]
