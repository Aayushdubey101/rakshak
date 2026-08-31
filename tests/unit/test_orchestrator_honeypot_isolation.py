"""InvestigationOrchestrator.run() is the enforcement chokepoint for task.md
phase 11: an engagement hook a caller wired up only runs if
isolation.authorize_engagement() grants it. Proves the hook cannot be
reached without every gate holding — including via a value a caller might
otherwise be tempted to trust from request data — and that an authorized
engagement writes an audit_logs entry naming the principal.
"""

from datetime import datetime, timezone

import pytest

from packages.agents.honeypot.isolation import ResearcherCredential
from packages.domain.investigations.orchestrator import InvestigationContext, InvestigationOrchestrator
from packages.shared.config.settings import get_settings
from packages.shared.schemas import ContentType, InvestigationRequest, Platform, StageState

_CREDENTIAL = ResearcherCredential(principal="researcher-1")


def _request(text: str = "hello") -> InvestigationRequest:
    return InvestigationRequest(
        platform=Platform.API,
        content_type=ContentType.TEXT,
        text=text,
        timestamp=datetime.now(timezone.utc),
    )


class _RaisingHook:
    """Fails the test loudly if the orchestrator ever calls it unauthorized."""

    async def __call__(self, ctx: InvestigationContext):
        raise AssertionError("engagement hook was invoked without authorization")


class _FakeAuditLogRepository:
    def __init__(self):
        self.calls = []

    async def record(self, **kwargs):
        self.calls.append(kwargs)

    async def list_for_target(self, target_type, target_id):
        return []


@pytest.mark.asyncio
async def test_engagement_never_runs_when_feature_flag_is_off(monkeypatch):
    monkeypatch.setattr(get_settings(), "HONEYPOT_ENABLED", False)
    orchestrator = InvestigationOrchestrator()

    outcome = await orchestrator.run(
        _request(), engagement=_RaisingHook(), researcher_credential=_CREDENTIAL, prior_confirmed_scam=True,
    )

    stage = next(s for s in outcome.report.stage_status if s.stage == "agent")
    assert stage.state == StageState.SKIPPED
    assert outcome.engagement is None


@pytest.mark.asyncio
async def test_engagement_never_runs_without_a_credential(monkeypatch):
    monkeypatch.setattr(get_settings(), "HONEYPOT_ENABLED", True)
    orchestrator = InvestigationOrchestrator()

    outcome = await orchestrator.run(
        _request(), engagement=_RaisingHook(), researcher_credential=None, prior_confirmed_scam=True,
    )

    assert outcome.engagement is None


@pytest.mark.asyncio
async def test_engagement_never_runs_without_a_confirmed_scam(monkeypatch):
    """Not even a forged claim of confirmation from outside the pipeline can
    substitute for this — `confirmed_scam` here is exactly what the pipeline's
    own detection stage (plus prior session state) produced, never client input."""
    monkeypatch.setattr(get_settings(), "HONEYPOT_ENABLED", True)
    orchestrator = InvestigationOrchestrator()

    outcome = await orchestrator.run(
        _request(text="hello, nothing scammy here"),
        engagement=_RaisingHook(), researcher_credential=_CREDENTIAL, prior_confirmed_scam=False,
    )

    assert outcome.engagement is None


@pytest.mark.asyncio
async def test_authorized_engagement_runs_and_writes_an_audit_log(monkeypatch):
    monkeypatch.setattr(get_settings(), "HONEYPOT_ENABLED", True)
    audit_log = _FakeAuditLogRepository()
    orchestrator = InvestigationOrchestrator(audit_log_repository=audit_log)

    async def hook(ctx: InvestigationContext):
        return "engaged"

    outcome = await orchestrator.run(
        _request(), engagement=hook, researcher_credential=_CREDENTIAL, prior_confirmed_scam=True,
    )

    assert outcome.engagement == "engaged"
    stage = next(s for s in outcome.report.stage_status if s.stage == "agent")
    assert stage.state == StageState.OK
    assert len(audit_log.calls) == 1
    assert audit_log.calls[0]["actor"] == _CREDENTIAL.principal
    assert audit_log.calls[0]["action"] == "honeypot_engagement"
    assert audit_log.calls[0]["target_id"] == outcome.report.investigation_id


@pytest.mark.asyncio
async def test_no_engagement_hook_never_writes_an_audit_log(monkeypatch):
    """No hook wired at all (every non-honeypot caller) means no attempt to
    authorize and no audit entry — this must stay silent for the default path."""
    monkeypatch.setattr(get_settings(), "HONEYPOT_ENABLED", True)
    audit_log = _FakeAuditLogRepository()
    orchestrator = InvestigationOrchestrator(audit_log_repository=audit_log)

    await orchestrator.run(_request(), researcher_credential=_CREDENTIAL, prior_confirmed_scam=True)

    assert audit_log.calls == []
