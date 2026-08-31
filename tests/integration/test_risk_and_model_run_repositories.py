"""SqlRiskAssessmentRepository / SqlModelRunRepository (packages/shared/db/repositories.py)
— phase 8's persistence layer for RiskSignal rows and model_runs audit rows.
"""

from packages.shared.db.repositories import get_model_run_repository, get_risk_assessment_repository
from packages.shared.db.engine import get_session_factory
from packages.shared.db.models import Investigation
from packages.shared.schemas.signals import RiskSignal, SignalSource


async def _seed_investigation(investigation_id: str) -> None:
    async with get_session_factory()() as db:
        db.add(Investigation(id=investigation_id, platform="api", content_type="text"))
        await db.commit()


async def test_record_and_load_signals_round_trips():
    await _seed_investigation("inv_1")
    repo = get_risk_assessment_repository()
    signals = [
        RiskSignal(source=SignalSource.PATTERN, score=0.6, label="lottery", confidence=0.6, weight=0.5),
        RiskSignal(source=SignalSource.ML_TEXT, score=0.9, label="spam", confidence=0.9,
                   model_id="mrm8488/bert-tiny-finetuned-sms-spam-detection", weight=0.3),
    ]

    await repo.record_signals("inv_1", signals)
    loaded = await repo.load_signals("inv_1")

    assert len(loaded) == 2
    assert {s.source for s in loaded} == {SignalSource.PATTERN, SignalSource.ML_TEXT}
    pattern = next(s for s in loaded if s.source == SignalSource.PATTERN)
    assert pattern.score == 0.6 and pattern.weight == 0.5


async def test_loaded_signals_refuse_to_the_same_number():
    """The actual "reproducible from stored signals" guarantee, end to end:
    persist, reload, fuse -- same number as fusing the originals."""
    from packages.domain.risk.fusion import fuse

    await _seed_investigation("inv_2")
    repo = get_risk_assessment_repository()
    original = [
        RiskSignal(source=SignalSource.PATTERN, score=0.4, label="x", confidence=0.4, weight=0.5),
        RiskSignal(source=SignalSource.ML_TEXT, score=0.8, label="x", confidence=0.8, weight=0.3),
    ]
    await repo.record_signals("inv_2", original)

    reloaded = await repo.load_signals("inv_2")

    assert fuse(original).risk_score == fuse(reloaded).risk_score


async def test_load_signals_for_unknown_investigation_is_empty():
    signals = await get_risk_assessment_repository().load_signals("does-not-exist")
    assert signals == []


async def test_record_model_run_writes_a_row():
    await _seed_investigation("inv_3")
    await get_model_run_repository().record_model_run(
        investigation_id="inv_3", stage="detection",
        model_id="mrm8488/bert-tiny-finetuned-sms-spam-detection", version="1", duration_ms=42,
    )

    from sqlalchemy import select
    from packages.shared.db.models import ModelRun

    async with get_session_factory()() as db:
        rows = (await db.scalars(select(ModelRun).where(ModelRun.investigation_id == "inv_3"))).all()

    assert len(rows) == 1
    assert rows[0].model_id == "mrm8488/bert-tiny-finetuned-sms-spam-detection"
    assert rows[0].duration_ms == 42
