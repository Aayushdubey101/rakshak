import asyncio
import pytest
from datetime import datetime, timezone

from packages.shared.schemas import (
    ContentType,
    InvestigationRequest,
    Platform,
    StageState,
    Verdict,
    new_investigation_id,
)
from packages.agents.honeypot.isolation import ResearcherCredential
from packages.domain.investigations.orchestrator import (
    InvestigationOrchestrator,
    InvestigationContext,
    StageBudget,
)

def build_dummy_request(text="hello"):
    return InvestigationRequest(
        platform=Platform.API,
        content_type=ContentType.TEXT,
        text=text,
        metadata={"session_id": "test"},
        timestamp=datetime.now(timezone.utc),
    )

_RESEARCHER = ResearcherCredential(principal="test-researcher")


@pytest.mark.asyncio
async def test_orchestrator_successful_pipeline(monkeypatch):
    """An authorized (feature-on, credentialed, confirmed-scam) engagement
    hook runs and its result flows through to the outcome — task.md phase 11
    gates this; tests/unit/test_orchestrator_honeypot_isolation.py covers the
    unauthorized paths."""
    from packages.shared.config.settings import get_settings

    monkeypatch.setattr(get_settings(), "HONEYPOT_ENABLED", True)
    orchestrator = InvestigationOrchestrator()
    req = build_dummy_request(text="hello world")

    async def dummy_engagement(ctx: InvestigationContext):
        return "agent_success"

    outcome = await orchestrator.run(
        req, engagement=dummy_engagement, researcher_credential=_RESEARCHER, prior_confirmed_scam=True,
    )

    assert outcome.report.investigation_id == req.investigation_id
    assert outcome.engagement == "agent_success"

    stage_names = [s.stage for s in outcome.report.stage_status]
    assert "ingestion" in stage_names
    assert "entities" in stage_names
    assert "detection" in stage_names
    assert "agent" in stage_names

@pytest.mark.asyncio
async def test_orchestrator_stage_degradation(monkeypatch):
    orchestrator = InvestigationOrchestrator()
    req = build_dummy_request(text="fail_detection")
    
    # Mock scam_detector to raise exception
    import packages.domain.risk.detector as detector
    
    async def mock_analyze(*args, **kwargs):
        raise ValueError("simulated detection failure")
    
    monkeypatch.setattr(detector, "analyze", mock_analyze)
    
    outcome = await orchestrator.run(req)
    
    # Detection should fail but pipeline should complete
    detection_status = next(s for s in outcome.report.stage_status if s.stage == "detection")
    assert detection_status.state == StageState.FAILED
    assert "simulated detection failure" in detection_status.error
    assert outcome.report.verdict == Verdict.LIKELY_SAFE  # default fallback

@pytest.mark.asyncio
async def test_orchestrator_stage_timeout(monkeypatch):
    # Set a tiny budget for detection
    budget = StageBudget(detection=0.01)
    orchestrator = InvestigationOrchestrator(budget=budget)
    req = build_dummy_request(text="timeout_detection")
    
    import packages.domain.risk.detector as detector
    
    async def mock_analyze(*args, **kwargs):
        await asyncio.sleep(0.1)
        return {"isScam": True}
        
    monkeypatch.setattr(detector, "analyze", mock_analyze)
    
    outcome = await orchestrator.run(req)
    
    detection_status = next(s for s in outcome.report.stage_status if s.stage == "detection")
    assert detection_status.state == StageState.FAILED
    assert "timed out" in detection_status.error

@pytest.mark.asyncio
async def test_orchestrator_unbuilt_stages_stay_skipped():
    orchestrator = InvestigationOrchestrator()
    req = build_dummy_request(text="hello world")

    outcome = await orchestrator.run(req)

    by_stage = {s.stage: s for s in outcome.report.stage_status}
    assert by_stage["threat_intel"].state == StageState.SKIPPED
    assert by_stage["risk_fusion"].state == StageState.SKIPPED
    assert by_stage["threat_intel"].error
    assert by_stage["risk_fusion"].error

@pytest.mark.asyncio
async def test_orchestrator_total_budget_enforced(monkeypatch):
    # Set a tiny total budget but long individual budgets
    budget = StageBudget(ingestion=5.0, entities=5.0, detection=5.0, total=0.1)
    orchestrator = InvestigationOrchestrator(budget=budget)
    req = build_dummy_request(text="timeout_pipeline")
    
    import packages.domain.risk.detector as detector
    
    async def mock_analyze(*args, **kwargs):
        await asyncio.sleep(0.5)
        return {"isScam": True}
        
    monkeypatch.setattr(detector, "analyze", mock_analyze)
    
    outcome = await orchestrator.run(req)
    
    pipeline_status = next((s for s in outcome.report.stage_status if s.stage == "pipeline"), None)
    assert pipeline_status is not None
    assert pipeline_status.state == StageState.FAILED
    assert "pipeline timed out" in pipeline_status.error


@pytest.mark.asyncio
async def test_protection_agent_runs_by_default_and_attaches_explanation_and_actions():
    """task.md phase 10's done-when: every consumer request gets an
    explanation + actions, with no engagement hook (no honeypot) involved."""
    orchestrator = InvestigationOrchestrator()
    req = build_dummy_request(
        text="Your SBI account is blocked. Send Rs 5000 to scammer@okaxis immediately to unblock."
    )

    outcome = await orchestrator.run(req)

    assert outcome.report.explanation
    assert outcome.report.recommended_actions
    protection_status = next(s for s in outcome.report.stage_status if s.stage == "protection")
    assert protection_status.state == StageState.OK


@pytest.mark.asyncio
async def test_protection_agent_degrades_gracefully_on_failure(monkeypatch):
    from packages.domain.investigations import orchestrator as orchestrator_module

    def _boom(_report):
        raise ValueError("simulated protection failure")

    monkeypatch.setattr(orchestrator_module.protection, "protect", _boom)
    orchestrator = InvestigationOrchestrator()
    req = build_dummy_request(text="hello world")

    outcome = await orchestrator.run(req)

    protection_status = next(s for s in outcome.report.stage_status if s.stage == "protection")
    assert protection_status.state == StageState.FAILED
    assert outcome.report.explanation is None
