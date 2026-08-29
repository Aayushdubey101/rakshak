"""The investigation pipeline, as one explicit function.

Every channel — web, Telegram, WhatsApp — hands an `InvestigationRequest` here
and gets exactly one `CanonicalReport` back. The pipeline is readable top to
bottom on purpose: to know what an investigation does, read `run()`.

Two rules shape everything below:

* **A stage failure degrades the report; it never aborts the investigation.**
  Each stage runs under its own timeout and its outcome is recorded in
  `stage_status`, so a dead model or a slow provider produces a partial report
  that says so, rather than a 500 or — worse — a confident "looks fine".
* **Every log line carries the investigation id**, so one identifier follows a
  request through the API, the workers, and the database.

Stages the target architecture defines but that are not built yet (threat
intelligence in phase 9, the ML/fusion split in phase 8) are recorded as
`SKIPPED` with the reason. Reporting a stage as `OK` when it never ran would
make `stage_status` a lie.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, TypeVar

from packages import threat_intel
from packages.agents import protection
from packages.agents.honeypot import isolation
from packages.agents.honeypot.isolation import ResearcherCredential
from packages.domain.entities import intelligence_extractor
from packages.domain.investigations.repository import AuditLogRepository
from packages.domain.risk import detector as scam_detector
from packages.domain.threat_intel.repository import ThreatIndicatorRepository
from packages.ingestion import MediaLoader, ingest
from packages.ml import url as ml_url
from packages.shared.config.settings import get_settings
from packages.shared.logging_config import investigation_id_var
from packages.shared.telemetry import investigation_span
from packages.shared.schemas import (
    CanonicalReport,
    EntityKind,
    ExtractedEntity,
    InvestigationRequest,
    NormalizedContent,
    Severity,
    StageState,
    StageStatus,
    ThreatIntelMatch,
    UrlFinding,
    Verdict,
)
from packages.shared.schemas.report import ModelMetadata

logger = logging.getLogger("uvicorn")

T = TypeVar("T")

# Which extractor bucket becomes which entity kind.
_ENTITY_KINDS: dict[str, EntityKind] = {
    "upiIds": EntityKind.UPI_ID,
    "phoneNumbers": EntityKind.PHONE,
    "bankAccounts": EntityKind.BANK_ACCOUNT,
    "phishingLinks": EntityKind.URL,
    "suspiciousKeywords": EntityKind.KEYWORD,
    "organizations": EntityKind.ORGANIZATION,
    "amounts": EntityKind.AMOUNT,
}


@dataclass(frozen=True)
class StageBudget:
    """Per-stage timeouts, and the total an interactive reply may spend.

    The agent budget is 8s, not the 15s the honeypot used to allow: a reply that
    outlasts the platform's own patience is a reply nobody receives. The
    interactive stages sum to less than `total`.
    """

    # ingestion was 5.0 -- too tight for a real vision-model transcription
    # call (packages/ingestion/image's gateway.try_generate(TaskKind.VISION)):
    # a thinking-capable model (e.g. gemini-flash-latest) routinely takes
    # 6-10s+ to transcribe a screenshot, so most image submissions blew this
    # budget and silently fell back to "image kept, untranscribed" --
    # detection then ran on ~empty text and under-flagged real scams.
    ingestion: float = 18.0
    entities: float = 2.0
    detection: float = 18.0
    agent: float = 8.0
    protection: float = 1.0
    total: float = 45.0


DEFAULT_BUDGET = StageBudget()


@dataclass(frozen=True)
class InvestigationContext:
    """What an engagement hook is allowed to see."""

    request: InvestigationRequest
    content: NormalizedContent
    detection: dict[str, Any]
    intelligence: dict[str, Any]


# Runs the channel-specific engagement (the honeypot today) after detection.
EngagementHook = Callable[[InvestigationContext], Awaitable[Any]]


@dataclass(frozen=True)
class InvestigationOutcome:
    report: CanonicalReport
    content: NormalizedContent
    detection: dict[str, Any] = field(default_factory=dict)
    intelligence: dict[str, Any] = field(default_factory=dict)
    engagement: Any = None


def severity_for(risk_score: int) -> Severity:
    if risk_score >= 80:
        return Severity.CRITICAL
    if risk_score >= 60:
        return Severity.HIGH
    if risk_score >= 30:
        return Severity.MEDIUM
    if risk_score > 0:
        return Severity.LOW
    return Severity.NONE


def _entities(intelligence: dict[str, Any]) -> tuple[ExtractedEntity, ...]:
    return tuple(
        ExtractedEntity(kind=kind, value=str(value), confidence=0.8, source=f"regex.{bucket}")
        for bucket, kind in _ENTITY_KINDS.items()
        for value in intelligence.get(bucket, [])
        if str(value).strip()
    )


def _url_findings(content: NormalizedContent, url_signals: dict[str, Any]) -> tuple[UrlFinding, ...]:
    """`url_signals` maps `UrlObservation.raw` -> the `RiskSignal` packages.ml.url.score()
    produced for it (item: previously this always reported Verdict.UNKNOWN unless
    ingestion's SSRF guard had already blocked the URL -- the lexical ruleset that
    actually looks at the URL string was built but never called from here)."""
    findings = []
    for observation in content.urls:
        if observation.blocked:
            findings.append(UrlFinding(
                url=observation.raw,
                normalized_url=observation.normalized,
                verdict=Verdict.SUSPICIOUS,
                reasons=(observation.block_reason,) if observation.block_reason else (),
            ))
            continue

        signal = url_signals.get(observation.raw)
        if signal is None:
            findings.append(UrlFinding(url=observation.raw, normalized_url=observation.normalized))
            continue

        verdict = Verdict.LIKELY_SAFE if signal.score == 0.0 else (
            Verdict.SUSPICIOUS if signal.score >= 0.5 else Verdict.UNKNOWN
        )
        reasons = tuple(signal.label.split(", ")) if signal.label != "no_lexical_flags" else ()
        findings.append(UrlFinding(
            url=observation.raw,
            normalized_url=observation.normalized,
            verdict=verdict,
            reasons=reasons,
            confidence=round(signal.score, 3),
        ))
    return tuple(findings)


class InvestigationOrchestrator:
    def __init__(
        self,
        *,
        budget: StageBudget = DEFAULT_BUDGET,
        media_loader: MediaLoader | None = None,
        threat_intel_repository: ThreatIndicatorRepository | None = None,
        audit_log_repository: AuditLogRepository | None = None,
    ):
        self.budget = budget
        self.media_loader = media_loader
        self.threat_intel_repository = threat_intel_repository
        self.audit_log_repository = audit_log_repository

    # -- stage plumbing -------------------------------------------------------

    async def _stage(
        self,
        name: str,
        factory: Callable[[], Awaitable[T]],
        *,
        timeout: float,
        default: T,
        investigation_id: str,
        stages: list[StageStatus],
    ) -> T:
        """Run one stage under its own timeout. Failure degrades, never raises."""
        started = time.monotonic()

        def _elapsed() -> int:
            return int((time.monotonic() - started) * 1000)

        try:
            result = await asyncio.wait_for(factory(), timeout=timeout)
        except asyncio.TimeoutError:
            logger.error(f"⏱️ [{investigation_id}] stage '{name}' timed out after {timeout}s")
            stages.append(StageStatus(
                stage=name, state=StageState.FAILED,
                error=f"timed out after {timeout}s", duration_ms=_elapsed(),
            ))
            return default
        except Exception as exc:
            logger.error(f"❌ [{investigation_id}] stage '{name}' failed: {exc}")
            stages.append(StageStatus(
                stage=name, state=StageState.FAILED, error=str(exc)[:200], duration_ms=_elapsed()
            ))
            return default

        logger.info(f"✅ [{investigation_id}] stage '{name}' ok in {_elapsed()}ms")
        stages.append(StageStatus(stage=name, state=StageState.OK, duration_ms=_elapsed()))
        return result

    # -- the pipeline ---------------------------------------------------------

    async def run(
        self,
        request: InvestigationRequest,
        *,
        history: list[dict] | None = None,
        engagement: EngagementHook | None = None,
        researcher_credential: ResearcherCredential | None = None,
        prior_confirmed_scam: bool = False,
    ) -> InvestigationOutcome:
        investigation_id = request.investigation_id
        stages: list[StageStatus] = []
        started = time.monotonic()

        content = NormalizedContent(investigation_id=investigation_id, text=request.text or "")
        intelligence: dict[str, Any] = {}
        detection: dict[str, Any] = {"isScam": False, "scamType": "other", "confidence": 0.0, "riskScore": 0}
        threat_intel_matches: tuple[ThreatIntelMatch, ...] = ()
        url_signals: dict[str, Any] = {}
        engagement_result = None

        logger.info(
            f"🔎 [{investigation_id}] investigation started "
            f"(platform={request.platform.value}, content={request.content_type.value})"
        )

        try:
            async with asyncio.timeout(self.budget.total):
                # 1. Ingestion
                content = await self._stage(
                    "ingestion",
                    lambda: ingest(request, media_loader=self.media_loader),
                    timeout=self.budget.ingestion,
                    default=content,
                    investigation_id=investigation_id,
                    stages=stages,
                )
                if content.rejections:
                    stages.append(StageStatus(
                        stage="ingestion.rejections",
                        state=StageState.DEGRADED,
                        error=content.rejections[0].detail,
                    ))

                text = content.analyzable_text

                # 1b. URL lexical risk (packages/ml/url) -- pure/offline/fast,
                # no timeout of its own needed the way an LLM- or network-backed
                # stage would.
                for observation in content.urls:
                    signal = await ml_url.score(observation)
                    if signal is not None:
                        url_signals[observation.raw] = signal

                # 2. Entity extraction — synchronous today, so it runs off the event loop
                intelligence = await self._stage(
                    "entities",
                    lambda: asyncio.to_thread(intelligence_extractor.extract, text),
                    timeout=self.budget.entities,
                    default={},
                    investigation_id=investigation_id,
                    stages=stages,
                )

                # 3. Threat intelligence
                if self.threat_intel_repository is not None:
                    entities = _entities(intelligence)

                    async def _run_threat_intel() -> tuple[ThreatIntelMatch, ...]:
                        matches, _signals = await threat_intel.analyze(
                            self.threat_intel_repository,
                            investigation_id=investigation_id,
                            entities=entities,
                        )
                        return matches

                    threat_intel_matches = await self._stage(
                        "threat_intel",
                        _run_threat_intel,
                        timeout=self.budget.entities,
                        default=(),
                        investigation_id=investigation_id,
                        stages=stages,
                    )
                else:
                    stages.append(StageStatus(
                        stage="threat_intel", state=StageState.SKIPPED,
                        error="no threat-intel repository configured",
                    ))

                # 4-6. ML signals, risk fusion, and LLM reasoning are one call today.
                # Phase 8 splits them into separate stages with their own budgets.
                detection = await self._stage(
                    "detection",
                    lambda: scam_detector.analyze(
                        text, history or [], allow_external_llm=request.consent_external_processing,
                    ),
                    timeout=self.budget.detection,
                    default=detection,
                    investigation_id=investigation_id,
                    stages=stages,
                )
                stages.append(StageStatus(
                    stage="risk_fusion",
                    state=StageState.SKIPPED,
                    error="folded into detection until phase 8",
                ))

                # 7. Agent decision — a caller-supplied engagement hook (the
                # honeypot, today) runs only if isolation.authorize_engagement()
                # grants it (task.md phase 11, rule #8). Even a hook a caller
                # wired up will not run unless every gate holds — this is the
                # single enforcement chokepoint every channel funnels through.
                confirmed_scam = prior_confirmed_scam or bool(detection.get("isScam"))
                authorized = engagement is not None and isolation.authorize_engagement(
                    feature_enabled=get_settings().HONEYPOT_ENABLED,
                    credential=researcher_credential,
                    confirmed_scam=confirmed_scam,
                )
                if authorized:
                    context = InvestigationContext(
                        request=request, content=content, detection=detection, intelligence=intelligence
                    )
                    engagement_result = await self._stage(
                        "agent",
                        lambda: engagement(context),
                        timeout=self.budget.agent,
                        default=None,
                        investigation_id=investigation_id,
                        stages=stages,
                    )
                    if self.audit_log_repository is not None:
                        try:
                            await self.audit_log_repository.record(
                                actor=researcher_credential.principal,
                                action="honeypot_engagement",
                                target_type="investigation",
                                target_id=investigation_id,
                                reason="confirmed scam, researcher-authorized engagement",
                            )
                        except Exception as exc:
                            logger.error(f"❌ [{investigation_id}] failed to write honeypot audit log: {exc}")
                elif engagement is not None:
                    stages.append(StageStatus(
                        stage="agent", state=StageState.SKIPPED,
                        error="honeypot engagement not authorized",
                    ))
                else:
                    stages.append(StageStatus(stage="agent", state=StageState.SKIPPED))

        except asyncio.TimeoutError:
            logger.error(f"⏱️ [{investigation_id}] investigation pipeline timed out after {self.budget.total}s")
            stages.append(StageStatus(
                stage="pipeline", state=StageState.FAILED,
                error=f"pipeline timed out after {self.budget.total}s",
                duration_ms=int((time.monotonic() - started) * 1000),
            ))

        # 8. Report
        report = self._build_report(
            request, content, detection, intelligence, stages, threat_intel_matches, url_signals,
        )

        # 9. Protection agent — the default agent for every consumer request
        # (task.md phase 10). Pure and additive over the report just built, so
        # it runs after `_build_report` and its stage entry is folded back in.
        async def _run_protection() -> CanonicalReport:
            return protection.protect(report)

        report = await self._stage(
            "protection", _run_protection,
            timeout=self.budget.protection, default=report,
            investigation_id=investigation_id, stages=stages,
        )
        report = report.model_copy(update={"stage_status": tuple(stages)})

        total_ms = int((time.monotonic() - started) * 1000)
        logger.info(
            f"🏁 [{investigation_id}] investigation complete in {total_ms}ms "
            f"(verdict={report.verdict.value}, risk={report.risk_score}, "
            f"degraded={report.is_degraded})"
        )
        return InvestigationOutcome(
            report=report,
            content=content,
            detection=detection,
            intelligence=intelligence,
            engagement=engagement_result,
        )

    def _build_report(
        self,
        request: InvestigationRequest,
        content: NormalizedContent,
        detection: dict[str, Any],
        intelligence: dict[str, Any],
        stages: list[StageStatus],
        threat_intel_matches: tuple[ThreatIntelMatch, ...] = (),
        url_signals: dict[str, Any] | None = None,
    ) -> CanonicalReport:
        url_signals = url_signals or {}
        text_risk_score = int(detection.get("riskScore", 0) or 0)
        # A URL's lexical risk (IP-literal host, brand lookalike, suspicious
        # TLD, ...) previously never reached risk_score/verdict at all -- a
        # link-only submission with no message text always fell through to
        # detection's default {isScam: False, riskScore: 0}. Folded in here,
        # not inside detector.analyze(), because that function only ever
        # receives text (packages/ml/url's own docstring already flagged
        # this exact gap).
        url_risk_score = round(max((s.score for s in url_signals.values()), default=0.0) * 100)
        risk_score = max(text_risk_score, url_risk_score)
        is_scam = bool(detection.get("isScam")) or url_risk_score >= 50

        return CanonicalReport(
            investigation_id=request.investigation_id,
            verdict=Verdict.SCAM if is_scam else Verdict.LIKELY_SAFE,
            risk_score=min(risk_score, 100),
            severity=severity_for(risk_score),
            confidence=min(max(float(detection.get("confidence", 0.0) or 0.0), 0.0), 1.0),
            scam_type=detection.get("scamType"),
            red_flags=tuple(detection.get("indicators", []))[:10],
            extracted_entities=_entities(intelligence),
            url_findings=_url_findings(content, url_signals),
            threat_intel=threat_intel_matches,
            model_metadata=(ModelMetadata(stage="detection", model_id=detection.get("method")),),
            stage_status=tuple(stages),
        )


_default_orchestrator = InvestigationOrchestrator()


async def investigate(
    request: InvestigationRequest,
    *,
    history: list[dict] | None = None,
    media_loader: MediaLoader | None = None,
    threat_intel_repository: ThreatIndicatorRepository | None = None,
    audit_log_repository: AuditLogRepository | None = None,
    engagement: EngagementHook | None = None,
    researcher_credential: ResearcherCredential | None = None,
    prior_confirmed_scam: bool = False,
) -> InvestigationOutcome:
    """Run one investigation on the default orchestrator.

    Sets `investigation_id_var` (packages.shared.logging_config) so every log
    line emitted anywhere during this call -- including nested awaits on
    other tasks sharing this context -- carries the id as a structured field,
    and wraps the call in a trace span (packages.shared.telemetry) carrying
    the same id as an attribute. Both are no-ops when their backing infra
    (JSON log handler, OTLP endpoint) isn't configured.
    """
    orchestrator = (
        InvestigationOrchestrator(
            media_loader=media_loader,
            threat_intel_repository=threat_intel_repository,
            audit_log_repository=audit_log_repository,
        )
        if media_loader is not None or threat_intel_repository is not None or audit_log_repository is not None
        else _default_orchestrator
    )
    token = investigation_id_var.set(request.investigation_id)
    try:
        with investigation_span(request.investigation_id):
            return await orchestrator.run(
                request, history=history, engagement=engagement,
                researcher_credential=researcher_credential, prior_confirmed_scam=prior_confirmed_scam,
            )
    finally:
        investigation_id_var.reset(token)
