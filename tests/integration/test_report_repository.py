"""SqlReportRepository (packages/shared/db/repositories.py) -- phase 12's
persistence layer for the one CanonicalReport an investigation produces.

Mirrors test_risk_and_model_run_repositories.py's `_seed_investigation`
pattern: `reports.investigation_id` is a foreign key, so a row must exist in
`investigations` first -- the same FK gap that keeps this repository unwired
from any live route today (see work.md's Phase 12 notes).
"""

from packages.reports.generator import generate_report
from packages.shared.db.engine import get_session_factory
from packages.shared.db.models import Investigation
from packages.shared.db.repositories import get_report_repository
from packages.shared.schemas import CanonicalReport, Severity, Verdict


async def _seed_investigation(investigation_id: str) -> None:
    async with get_session_factory()() as db:
        db.add(Investigation(id=investigation_id, platform="api", content_type="text"))
        await db.commit()


def _report(investigation_id: str, **overrides) -> CanonicalReport:
    base = dict(
        investigation_id=investigation_id,
        verdict=Verdict.SCAM,
        risk_score=80,
        severity=Severity.HIGH,
        confidence=0.8,
        scam_type="upi_fraud",
    )
    return CanonicalReport(**{**base, **overrides})


async def test_save_and_get_round_trips():
    await _seed_investigation("inv_report_1")
    repo = get_report_repository()
    report = _report("inv_report_1", red_flags=("urgency",))

    await repo.save(report)
    loaded = await repo.get("inv_report_1")

    assert loaded is not None
    assert loaded.investigation_id == "inv_report_1"
    assert loaded.verdict == Verdict.SCAM
    assert loaded.risk_score == 80
    assert loaded.red_flags == ("urgency",)


async def test_save_is_an_upsert_not_a_duplicate():
    await _seed_investigation("inv_report_2")
    repo = get_report_repository()

    await repo.save(_report("inv_report_2", risk_score=10))
    await repo.save(_report("inv_report_2", risk_score=95))

    from sqlalchemy import select

    from packages.shared.db.models import Report

    async with get_session_factory()() as db:
        rows = (
            await db.scalars(select(Report).where(Report.investigation_id == "inv_report_2"))
        ).all()

    assert len(rows) == 1
    loaded = await repo.get("inv_report_2")
    assert loaded.risk_score == 95


async def test_get_for_unknown_investigation_is_none():
    assert await get_report_repository().get("does-not-exist") is None


async def test_generate_report_persists_through_the_real_repository():
    await _seed_investigation("inv_report_3")
    repo = get_report_repository()
    report = _report("inv_report_3")

    await generate_report(report, repository=repo)

    assert (await repo.get("inv_report_3")).investigation_id == "inv_report_3"
