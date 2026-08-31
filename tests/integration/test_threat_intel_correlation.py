"""Phase 9's literal done-when, against the real SQLAlchemy repository:
a second investigation with a shared indicator correlates to the first and
both link to one `scam_campaigns` row.
"""

from sqlalchemy import select

from packages.shared.db.engine import get_session_factory
from packages.shared.db.models import Investigation, ThreatIndicator
from packages.shared.db.repositories import get_domain_reputation_repository, get_threat_indicator_repository


async def _seed_investigation(investigation_id: str) -> None:
    async with get_session_factory()() as db:
        db.add(Investigation(id=investigation_id, platform="api", content_type="text"))
        await db.commit()


async def test_shared_indicator_correlates_second_investigation_to_the_first():
    await _seed_investigation("inv_a")
    await _seed_investigation("inv_b")
    repository = get_threat_indicator_repository()

    first_matches = await repository.correlate(
        investigation_id="inv_a", kind="upi_id", value="scammer@ybl",
        normalized="scammer@ybl", value_hash="hash_upi_1",
    )
    second_matches = await repository.correlate(
        investigation_id="inv_b", kind="upi_id", value="scammer@ybl",
        normalized="scammer@ybl", value_hash="hash_upi_1",
    )

    assert first_matches == ()
    assert len(second_matches) == 1
    assert second_matches[0].investigation_id == "inv_a"
    assert second_matches[0].campaign_id is not None

    async with get_session_factory()() as db:
        indicator = await db.scalar(
            select(ThreatIndicator).where(ThreatIndicator.value_hash == "hash_upi_1")
        )

    assert indicator.occurrence_count == 2
    assert indicator.campaign_id == second_matches[0].campaign_id


async def test_unrelated_indicators_do_not_correlate():
    await _seed_investigation("inv_c")
    await _seed_investigation("inv_d")
    repository = get_threat_indicator_repository()

    await repository.correlate(
        investigation_id="inv_c", kind="upi_id", value="one@ybl", normalized="one@ybl", value_hash="hash_a",
    )
    matches = await repository.correlate(
        investigation_id="inv_d", kind="upi_id", value="two@ybl", normalized="two@ybl", value_hash="hash_b",
    )

    assert matches == ()


async def test_third_investigation_joins_the_existing_campaign_not_a_new_one():
    await _seed_investigation("inv_e")
    await _seed_investigation("inv_f")
    await _seed_investigation("inv_g")
    repository = get_threat_indicator_repository()

    await repository.correlate(
        investigation_id="inv_e", kind="phone", value="9876543210",
        normalized="9876543210", value_hash="hash_phone_1",
    )
    second_matches = await repository.correlate(
        investigation_id="inv_f", kind="phone", value="9876543210",
        normalized="9876543210", value_hash="hash_phone_1",
    )
    third_matches = await repository.correlate(
        investigation_id="inv_g", kind="phone", value="9876543210",
        normalized="9876543210", value_hash="hash_phone_1",
    )

    campaign_ids = {m.campaign_id for m in second_matches} | {m.campaign_id for m in third_matches}
    assert len(campaign_ids) == 1
    assert len(third_matches) == 2  # correlates against both inv_e and inv_f


async def test_domain_reputation_trends_toward_repeated_lexical_score():
    repository = get_domain_reputation_repository()

    first = await repository.record_sighting("sbi-verify.xyz", 0.2)
    second = await repository.record_sighting("sbi-verify.xyz", 0.9)

    assert first.is_repeat is False
    assert first.reputation_score == 0.2
    assert second.is_repeat is True
    assert first.reputation_score < second.reputation_score < 0.9
