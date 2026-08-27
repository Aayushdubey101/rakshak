"""SQLAlchemy implementations of the Protocols in
`packages/domain/investigations/repository.py`. This is the only place an
ORM session is allowed to exist.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from packages.domain.threat_intel.repository import CorrelationMatch, DomainReputation
from packages.shared.config.settings import get_settings
from packages.shared.db.models import (
    ApiKey,
    AuditLog,
    Domain,
    Entity,
    Investigation,
    Message,
    ModelRun,
    Report,
    RiskAssessment,
    ScamCampaign,
    ThreatIndicator,
    User,
)
from packages.shared.privacy import EvidenceState
from packages.shared.schemas import parse_flexible_timestamp
from packages.shared.schemas.report import CanonicalReport
from packages.shared.schemas.signals import RiskSignal, SignalSource
from packages.shared.security.api_keys import ApiKeyPrincipal, generate_api_key, hash_api_key

logger = logging.getLogger("uvicorn")

# session-dict bucket name -> EntityKind value. Mirrors
# packages.domain.investigations.orchestrator._ENTITY_KINDS; the honeypot
# session dict (session_manager.py) and the orchestrator's intelligence dict
# share the same five bucket names by construction (both come from
# intelligence_extractor.extract()).
_BUCKET_TO_KIND = {
    "upiIds": "upi_id",
    "phoneNumbers": "phone",
    "bankAccounts": "bank_account",
    "phishingLinks": "url",
    "suspiciousKeywords": "keyword",
}
_KIND_TO_BUCKET = {v: k for k, v in _BUCKET_TO_KIND.items()}


def _utc(ts: Optional[Any]) -> datetime:
    if ts is None:
        return datetime.now(timezone.utc)
    return parse_flexible_timestamp(ts)


class SqlEvidenceRepository:
    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def log_session(self, session: dict[str, Any]) -> None:
        session_id = session.get("sessionId")
        if not session_id:
            return

        intel = session.get("extractedIntelligence", {})
        is_scam = bool(session.get("scamDetected"))
        risk_score = min(_intelligence_score(intel), 100) if is_scam else 0

        async with self._session_factory() as db:
            investigation = await db.get(Investigation, session_id)
            if investigation is None:
                created_at = _utc(session.get("startTime"))
                retention_days = get_settings().RETENTION_DAYS_MESSAGES
                investigation = Investigation(
                    id=session_id,
                    platform="api",
                    content_type="text",
                    data_origin="honeypot_research",
                    created_at=created_at,
                    purge_at=(
                        created_at + timedelta(days=retention_days) if retention_days else None
                    ),
                )
                db.add(investigation)

            investigation.verdict = "scam" if is_scam else "likely_safe"
            investigation.risk_score = risk_score
            investigation.scam_type = session.get("scamType")
            investigation.evidence_state = EvidenceState.RETAINED.value

            await db.execute(delete(Message).where(Message.investigation_id == session_id))
            for msg in session.get("conversationHistory", []):
                db.add(Message(
                    investigation_id=session_id,
                    sender=msg.get("sender", "unknown"),
                    text=msg.get("text", ""),
                    timestamp=_utc(msg.get("timestamp")),
                ))

            await db.execute(delete(Entity).where(Entity.investigation_id == session_id))
            for bucket, kind in _BUCKET_TO_KIND.items():
                for value in intel.get(bucket, []):
                    db.add(Entity(
                        investigation_id=session_id, kind=kind, value=str(value), source="regex",
                    ))

            existing_report = await db.scalar(
                select(Report).where(Report.investigation_id == session_id)
            )
            if existing_report is None:
                db.add(Report(investigation_id=session_id, payload=session))
            else:
                existing_report.payload = session

            await db.commit()

    async def get_evidence(self) -> dict[str, Any]:
        """Honeypot-origin data only (phase 11: stored separately from
        consumer investigations, even though both live in these tables) —
        `Investigation.data_origin` scopes every query here."""
        async with self._session_factory() as db:
            honeypot_ids = select(Investigation.id).where(Investigation.data_origin == "honeypot_research")

            reports = (await db.scalars(
                select(Report).where(Report.investigation_id.in_(honeypot_ids))
            )).all()
            sessions = {r.investigation_id: r.payload for r in reports}

            entities = (await db.scalars(
                select(Entity).where(Entity.investigation_id.in_(honeypot_ids))
            )).all()
            master_intel = {bucket: set() for bucket in _BUCKET_TO_KIND}
            for entity in entities:
                bucket = _KIND_TO_BUCKET.get(entity.kind)
                if bucket:
                    master_intel[bucket].add(entity.value)

            total_scams = len((await db.scalars(
                select(Investigation).where(
                    Investigation.verdict == "scam", Investigation.data_origin == "honeypot_research",
                )
            )).all())

            return {
                "sessions": sessions,
                "masterIntel": {bucket: sorted(values) for bucket, values in master_intel.items()},
                "totalScamsDetected": total_scams,
            }


class SqlAuditLogRepository:
    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def record(
        self,
        *,
        actor: str,
        action: str,
        target_type: str,
        target_id: str,
        reason: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        async with self._session_factory() as db:
            db.add(AuditLog(
                actor=actor, action=action, target_type=target_type, target_id=target_id,
                reason=reason, audit_metadata=metadata or {},
            ))
            await db.commit()

    async def list_for_target(self, target_type: str, target_id: str) -> list[dict[str, Any]]:
        async with self._session_factory() as db:
            rows = (await db.scalars(
                select(AuditLog).where(
                    AuditLog.target_type == target_type, AuditLog.target_id == target_id
                )
            )).all()
            return [
                {
                    "id": r.id, "actor": r.actor, "action": r.action, "reason": r.reason,
                    "metadata": r.audit_metadata, "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ]


class SqlInvestigationRepository:
    def __init__(self, session_factory: async_sessionmaker, audit_log: SqlAuditLogRepository):
        self._session_factory = session_factory
        self._audit_log = audit_log

    async def purge_expired(self, *, now: Optional[datetime] = None) -> int:
        now = now or datetime.now(timezone.utc)
        async with self._session_factory() as db:
            expired = (await db.scalars(
                select(Investigation).where(
                    Investigation.purge_at.is_not(None), Investigation.purge_at <= now
                )
            )).all()
            for investigation in expired:
                investigation.evidence_state = EvidenceState.PURGED.value
                await db.execute(delete(Message).where(Message.investigation_id == investigation.id))
                await db.execute(delete(Entity).where(Entity.investigation_id == investigation.id))
                await db.execute(delete(Report).where(Report.investigation_id == investigation.id))
            await db.commit()

        for investigation in expired:
            await self._audit_log.record(
                actor="retention-purge-job", action="purge",
                target_type="investigation", target_id=investigation.id,
                reason="retention period elapsed",
            )
        return len(expired)

    async def delete_for_owner(self, session_id: str, *, actor: str, reason: str) -> bool:
        async with self._session_factory() as db:
            investigation = await db.get(Investigation, session_id)
            if investigation is None:
                return False
            await db.execute(delete(Message).where(Message.investigation_id == session_id))
            await db.execute(delete(Entity).where(Entity.investigation_id == session_id))
            await db.execute(delete(Report).where(Report.investigation_id == session_id))
            await db.delete(investigation)
            await db.commit()

        await self._audit_log.record(
            actor=actor, action="delete", target_type="investigation",
            target_id=session_id, reason=reason,
        )
        return True

    async def create_pending(
        self, investigation_id: str, *, platform: str, content_type: str, user_id: str | None = None
    ) -> None:
        async with self._session_factory() as db:
            existing = await db.get(Investigation, investigation_id)
            if existing is None:
                db.add(Investigation(
                    id=investigation_id, platform=platform, content_type=content_type, user_id=user_id,
                ))
                await db.commit()

    async def exists(self, investigation_id: str) -> bool:
        async with self._session_factory() as db:
            return await db.get(Investigation, investigation_id) is not None


class SqlRiskAssessmentRepository:
    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def record_signals(self, investigation_id: str, signals: list[RiskSignal]) -> None:
        if not signals:
            return
        async with self._session_factory() as db:
            for signal in signals:
                db.add(RiskAssessment(
                    investigation_id=investigation_id, source=signal.source.value,
                    score=signal.score, label=signal.label, confidence=signal.confidence,
                    model_id=signal.model_id, weight=signal.weight,
                ))
            await db.commit()

    async def load_signals(self, investigation_id: str) -> list[RiskSignal]:
        async with self._session_factory() as db:
            rows = (await db.scalars(
                select(RiskAssessment).where(RiskAssessment.investigation_id == investigation_id)
            )).all()
            return [
                RiskSignal(
                    source=SignalSource(row.source), score=row.score, label=row.label,
                    confidence=row.confidence, model_id=row.model_id, weight=row.weight,
                )
                for row in rows
            ]


class SqlModelRunRepository:
    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def record_model_run(
        self, *, investigation_id: str, stage: str, model_id: str, version: str, duration_ms: int
    ) -> None:
        async with self._session_factory() as db:
            db.add(ModelRun(
                investigation_id=investigation_id, stage=stage,
                model_id=model_id, version=version, duration_ms=duration_ms,
            ))
            await db.commit()


class SqlThreatIndicatorRepository:
    """Correlates one investigation's indicator against every other
    investigation's occurrence of the same `(kind, value_hash)`.

    Prior occurrences are read from `entities` — already investigation-scoped
    and already carrying `kind`/`value`/`normalized_value` — rather than a new
    table, since task.md's phase 7 table list is fixed and phase 9 reuses it.
    This investigation's own occurrence is written to `entities` too (so a
    *future* investigation can match against it), and `threat_indicators`
    tracks the global dedup + occurrence count + campaign link.
    """

    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def correlate(
        self, *, investigation_id: str, kind: str, value: str, normalized: str, value_hash: str
    ) -> tuple[CorrelationMatch, ...]:
        async with self._session_factory() as db:
            prior_entities = (await db.scalars(
                select(Entity).where(
                    Entity.kind == kind,
                    Entity.normalized_value == normalized,
                    Entity.investigation_id != investigation_id,
                )
            )).all()

            already_recorded = await db.scalar(
                select(Entity).where(
                    Entity.investigation_id == investigation_id,
                    Entity.kind == kind,
                    Entity.normalized_value == normalized,
                )
            )
            if already_recorded is None:
                db.add(Entity(
                    investigation_id=investigation_id, kind=kind, value=value,
                    normalized_value=normalized, confidence=1.0, source="threat_intel",
                ))

            indicator = await db.scalar(
                select(ThreatIndicator).where(
                    ThreatIndicator.kind == kind, ThreatIndicator.value_hash == value_hash,
                )
            )
            now = datetime.now(timezone.utc)
            if indicator is None:
                indicator = ThreatIndicator(
                    kind=kind, value_hash=value_hash, first_seen=now, last_seen=now, occurrence_count=1,
                )
                db.add(indicator)
            else:
                indicator.last_seen = now
                indicator.occurrence_count += 1

            if prior_entities and indicator.campaign_id is None:
                campaign = ScamCampaign(
                    name=f"{kind}:{value[:64]}",
                    description=f"Correlated via shared {kind} indicator across investigations.",
                )
                db.add(campaign)
                await db.flush()
                indicator.campaign_id = campaign.id

            campaign_id = indicator.campaign_id
            await db.commit()

            return tuple(
                CorrelationMatch(
                    investigation_id=e.investigation_id, value=e.value,
                    first_seen=indicator.first_seen, campaign_id=campaign_id,
                )
                for e in prior_entities
            )


class SqlDomainReputationRepository:
    """Aggregates a domain's lexical score across every sighting into a
    running reputation, so a domain seen repeatedly triggering red flags
    trends risky and one that mostly scores clean trends down."""

    _EMA_ALPHA = 0.3

    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def record_sighting(self, domain: str, lexical_score: float) -> DomainReputation:
        async with self._session_factory() as db:
            row = await db.scalar(select(Domain).where(Domain.name == domain))
            now = datetime.now(timezone.utc)
            if row is None:
                row = Domain(name=domain, first_seen=now, last_seen=now, reputation_score=lexical_score)
                db.add(row)
                is_repeat = False
            else:
                row.last_seen = now
                previous = row.reputation_score or 0.0
                row.reputation_score = (
                    self._EMA_ALPHA * lexical_score + (1 - self._EMA_ALPHA) * previous
                )
                is_repeat = True
            await db.commit()
            return DomainReputation(domain=domain, reputation_score=row.reputation_score, is_repeat=is_repeat)


class SqlReportRepository:
    """Persists `CanonicalReport.model_dump()` into the same `reports` table
    `SqlEvidenceRepository` already writes honeypot session snapshots to --
    task.md's phase 7 table list is fixed, and this is exactly the row shape
    `Report.payload`'s own docstring names. The two write under different
    keys (a honeypot session's persistent sessionId vs. a fresh per-message
    investigation_id), so they never collide.

    Requires an `investigations.id == report.investigation_id` row to already
    exist (`reports.investigation_id` is a foreign key) -- not yet true for a
    live web/Telegram/WhatsApp request, since nothing on that path creates an
    `Investigation` row today. Built and tested against the real repository;
    not called from a live route yet -- see work.md's Phase 12 notes.
    """

    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def save(self, report: CanonicalReport) -> None:
        async with self._session_factory() as db:
            existing = await db.scalar(
                select(Report).where(Report.investigation_id == report.investigation_id)
            )
            payload = report.model_dump(mode="json")
            if existing is None:
                db.add(Report(investigation_id=report.investigation_id, payload=payload))
            else:
                existing.payload = payload
            await db.commit()

    async def get(self, investigation_id: str) -> Optional[CanonicalReport]:
        async with self._session_factory() as db:
            row = await db.scalar(select(Report).where(Report.investigation_id == investigation_id))
            return CanonicalReport.model_validate(row.payload) if row is not None else None

    async def list_summaries(self, *, limit: int = 50, user_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Most recent reports first, flattened with the owning `Investigation`
        row's `platform`/`content_type` -- `CanonicalReport` itself carries
        neither (it's channel-agnostic by design, rule #3), but a web
        investigations list needs them for its Source/Type columns.
        `user_id` scopes to one owner's own investigations (a `user:`-principal
        caller); omitted for an admin-scoped service key, which sees
        everything."""
        async with self._session_factory() as db:
            query = (
                select(Report, Investigation)
                .join(Investigation, Investigation.id == Report.investigation_id)
                .order_by(Report.generated_at.desc())
                .limit(limit)
            )
            if user_id is not None:
                query = query.where(Investigation.user_id == user_id)
            rows = (await db.execute(query)).all()
            return [
                {
                    **report.payload,  # already carries investigation_id, generated_at, etc.
                    "platform": investigation.platform,
                    "content_type": investigation.content_type,
                }
                for report, investigation in rows
            ]


class SqlUserRepository:
    """End-user accounts (email + password), distinct from `SqlApiKeyRepository`'s
    service credentials. `password_hash` is `None` for a user row created some
    other way (e.g. a future platform-account link) that has never set one."""

    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def get_by_email(self, email: str) -> Optional[User]:
        async with self._session_factory() as db:
            return await db.scalar(select(User).where(User.email == email))

    async def create(self, *, email: str, password_hash: str) -> User:
        async with self._session_factory() as db:
            user = User(email=email, password_hash=password_hash)
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user

    async def get(self, user_id: str) -> Optional[User]:
        async with self._session_factory() as db:
            return await db.get(User, user_id)

    async def set_password(self, user_id: str, password_hash: str) -> bool:
        async with self._session_factory() as db:
            user = await db.get(User, user_id)
            if user is None:
                return False
            user.password_hash = password_hash
            await db.commit()
            return True


class SqlApiKeyRepository:
    """Real scoped credentials (task.md phase 14), replacing the single
    shared `API_SECRET_KEY`. Only a sha256 hash is ever persisted."""

    def __init__(self, session_factory: async_sessionmaker):
        self._session_factory = session_factory

    async def create(self, *, principal: str, scopes: frozenset[str]) -> tuple[str, str]:
        plaintext = generate_api_key()
        async with self._session_factory() as db:
            row = ApiKey(
                key_hash=hash_api_key(plaintext), principal=principal, scopes=sorted(scopes),
            )
            db.add(row)
            await db.commit()
            await db.refresh(row)
            return row.id, plaintext

    async def verify(self, plaintext: str) -> Optional[ApiKeyPrincipal]:
        async with self._session_factory() as db:
            row = await db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(plaintext)))
            if row is None or row.revoked_at is not None:
                return None
            row.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            return ApiKeyPrincipal(principal=row.principal, scopes=frozenset(row.scopes), key_id=row.id)

    async def revoke(self, key_id: str) -> bool:
        async with self._session_factory() as db:
            row = await db.get(ApiKey, key_id)
            if row is None or row.revoked_at is not None:
                return False
            row.revoked_at = datetime.now(timezone.utc)
            await db.commit()
            return True

    async def list_keys(self) -> list[dict[str, Any]]:
        async with self._session_factory() as db:
            rows = (await db.scalars(select(ApiKey))).all()
            return [
                {
                    "id": r.id, "principal": r.principal, "scopes": r.scopes,
                    "created_at": r.created_at.isoformat(),
                    "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                    "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                }
                for r in rows
            ]


def _intelligence_score(intel: dict[str, Any]) -> int:
    score = 0
    score += len(intel.get("upiIds", [])) * 30
    score += len(intel.get("phoneNumbers", [])) * 20
    score += len(intel.get("bankAccounts", [])) * 25
    score += len(intel.get("phishingLinks", [])) * 15
    return score


# Module-level singletons, same pattern as `evidence_store = EvidenceStore()`
# and `webhook_dedup = MessageDeduplicator()` elsewhere in this codebase.
# `lru_cache` (not import-time construction) so tests can call
# `packages.shared.db.engine.reset_engine_cache()` + these `.cache_clear()`s
# to point at a fresh sqlite file per test without reimporting modules.

@lru_cache()
def get_evidence_repository() -> SqlEvidenceRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlEvidenceRepository(get_session_factory())


@lru_cache()
def get_audit_log_repository() -> SqlAuditLogRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlAuditLogRepository(get_session_factory())


@lru_cache()
def get_investigation_repository() -> SqlInvestigationRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlInvestigationRepository(get_session_factory(), get_audit_log_repository())


@lru_cache()
def get_risk_assessment_repository() -> SqlRiskAssessmentRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlRiskAssessmentRepository(get_session_factory())


@lru_cache()
def get_model_run_repository() -> SqlModelRunRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlModelRunRepository(get_session_factory())


@lru_cache()
def get_threat_indicator_repository() -> SqlThreatIndicatorRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlThreatIndicatorRepository(get_session_factory())


@lru_cache()
def get_domain_reputation_repository() -> SqlDomainReputationRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlDomainReputationRepository(get_session_factory())


@lru_cache()
def get_report_repository() -> SqlReportRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlReportRepository(get_session_factory())


@lru_cache()
def get_user_repository() -> SqlUserRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlUserRepository(get_session_factory())


@lru_cache()
def get_api_key_repository() -> SqlApiKeyRepository:
    from packages.shared.db.engine import get_session_factory

    return SqlApiKeyRepository(get_session_factory())


def reset_repository_cache() -> None:
    get_evidence_repository.cache_clear()
    get_audit_log_repository.cache_clear()
    get_investigation_repository.cache_clear()
    get_risk_assessment_repository.cache_clear()
    get_model_run_repository.cache_clear()
    get_threat_indicator_repository.cache_clear()
    get_domain_reputation_repository.cache_clear()
    get_report_repository.cache_clear()
    get_user_repository.cache_clear()
    get_api_key_repository.cache_clear()
