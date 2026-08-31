from datetime import datetime, timezone

from packages.domain.investigations.orchestrator import InvestigationOrchestrator
from packages.domain.threat_intel.repository import CorrelationMatch
from packages.shared.schemas import ContentType, InvestigationRequest, Platform, StageState, new_investigation_id


def _request(text: str) -> InvestigationRequest:
    return InvestigationRequest(
        investigation_id=new_investigation_id(),
        platform=Platform.API,
        content_type=ContentType.TEXT,
        text=text,
        timestamp=datetime.now(timezone.utc),
    )


class _FakeThreatIntelRepository:
    """Mirrors `SqlThreatIndicatorRepository.correlate`'s contract without a
    database: remembers which investigation first produced each indicator and
    reports every later investigation that shares it."""

    def __init__(self):
        self._first_seen: dict[str, tuple[str, datetime]] = {}

    async def correlate(self, *, investigation_id, kind, value, normalized, value_hash):
        prior = self._first_seen.get(value_hash)
        if prior is None:
            self._first_seen[value_hash] = (investigation_id, datetime.now(timezone.utc))
            return ()
        prior_investigation_id, first_seen = prior
        if prior_investigation_id == investigation_id:
            return ()
        return (CorrelationMatch(
            investigation_id=prior_investigation_id, value=value, first_seen=first_seen, campaign_id="camp_1",
        ),)


async def test_threat_intel_stage_skipped_without_a_repository():
    orchestrator = InvestigationOrchestrator()

    outcome = await orchestrator.run(_request("hello"))

    stage = next(s for s in outcome.report.stage_status if s.stage == "threat_intel")
    assert stage.state == StageState.SKIPPED
    assert stage.error


async def test_second_investigation_with_shared_indicator_correlates_to_the_first():
    repository = _FakeThreatIntelRepository()
    orchestrator = InvestigationOrchestrator(threat_intel_repository=repository)
    scam_text = "Pay urgently to scammer@ybl or your account will be blocked"

    first = await orchestrator.run(_request(scam_text))
    second = await orchestrator.run(_request(scam_text))

    first_stage = next(s for s in first.report.stage_status if s.stage == "threat_intel")
    second_stage = next(s for s in second.report.stage_status if s.stage == "threat_intel")
    assert first_stage.state == StageState.OK
    assert second_stage.state == StageState.OK

    assert first.report.threat_intel == ()
    assert len(second.report.threat_intel) == 1
    match = second.report.threat_intel[0]
    assert match.indicator == "scammer@ybl"
    assert match.campaign_id == "camp_1"
