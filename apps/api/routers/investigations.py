import time
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel
from typing import Optional

from packages.shared.schemas import InvestigationRequest
from packages.shared.schemas.investigation import MediaRef, Platform, new_investigation_id
from packages.domain.investigations import session_manager
from packages.domain.investigations.orchestrator import investigate
from packages.ingestion.limits import DEFAULT_LIMITS, sniff
from packages.reports.generator import generate_report
from packages.reports.serializers import to_web
from packages.shared.db.repositories import (
    get_audit_log_repository,
    get_evidence_repository,
    get_investigation_repository,
    get_report_repository,
)
from packages.shared.queue import get_arq_pool
from packages.shared.storage.object_store import get_object_store
from apps.api.honeypot_adapter import HoneypotRequest, HoneypotResponse, process_honeypot_request
from apps.api.dependencies import get_principal, require_scope
from packages.shared.config.settings import get_settings
from packages.ml.inference import hf as hf_models
from packages.llm.providers.gemini.pool import gemini_pool
from packages.shared.security.api_keys import ApiKeyPrincipal, SCOPE_ADMIN, SCOPE_ANALYZE, SCOPE_READ_INVESTIGATIONS, SCOPE_RESEARCH_HONEYPOT
from packages.shared.security.tokens import issue_token

router = APIRouter(prefix="/api", tags=["investigations"])


async def _object_store_media_loader(ref: MediaRef) -> bytes:
    """Resolves an uploaded file's `MediaRef.uri` (an object-storage key) back
    to bytes so `packages.ingestion.ingest()` can actually OCR/extract it --
    without this, media is recorded but never read (see
    `packages/ingestion/__init__.py`'s own `media_loader is None` branch)."""
    return await get_object_store().get(ref.uri)


def _owner_user_id(principal: ApiKeyPrincipal) -> Optional[str]:
    if principal.principal.startswith("user:"):
        return principal.principal.removeprefix("user:")
    return None


async def _audit(action: str, *, actor: str, target_type: str, target_id: str) -> None:
    """Best-effort: an audit-log write failing must never fail the request it
    describes (same convention as the orchestrator's own honeypot-engagement
    audit write)."""
    try:
        await get_audit_log_repository().record(
            actor=actor, action=action, target_type=target_type, target_id=target_id,
        )
    except Exception:
        pass  # nosec B110


class TokenResponse(BaseModel):
    token: str
    expires_at: int
    scopes: list[str]


@router.post("/v1/auth/token", response_model=TokenResponse)
async def issue_scoped_token(principal: ApiKeyPrincipal = Depends(get_principal)):
    """Exchanges a valid API key for a short-lived bearer token (task.md
    phase 14). Scoped identically to the key that requested it -- a token
    can never grant more than its issuing key already had."""
    token, expires_at = issue_token(principal, secret=get_settings().API_SECRET_KEY)
    return TokenResponse(token=token, expires_at=expires_at, scopes=sorted(principal.scopes))


@router.post("/honeypot/", dependencies=[Depends(require_scope(SCOPE_ANALYZE))], response_model=HoneypotResponse)
async def process_message_legacy(
    req: HoneypotRequest, background_tasks: BackgroundTasks,
    x_researcher_key: Optional[str] = Header(None, alias="X-Researcher-Key"),
):
    return await process_honeypot_request(
        req, background_tasks, get_settings().STRICT_RESPONSE_MODE, researcher_key=x_researcher_key,
    )

@router.post("/v1/investigations", dependencies=[Depends(require_scope(SCOPE_ANALYZE))])
async def create_investigation(request: InvestigationRequest, principal: ApiKeyPrincipal = Depends(get_principal)):
    await _audit("investigation_created", actor=principal.principal, target_type="investigation", target_id=request.investigation_id)
    await get_investigation_repository().create_pending(
        request.investigation_id, platform=request.platform.value, content_type=request.content_type.value,
        user_id=_owner_user_id(principal),
    )
    outcome = await investigate(request, media_loader=_object_store_media_loader)
    await generate_report(outcome.report, repository=get_report_repository())
    return to_web(outcome.report)


@router.post("/v1/investigations/upload", dependencies=[Depends(require_scope(SCOPE_ANALYZE))])
async def create_investigation_upload(
    file: UploadFile = File(...),
    text: Optional[str] = Form(None),
    principal: ApiKeyPrincipal = Depends(get_principal),
):
    """Image/document analysis (web `analyze-form.tsx`'s upload tabs). A
    multipart counterpart to `/v1/investigations` -- that endpoint only
    accepts a `MediaRef` pointing at an object already in storage; this is
    what actually puts a freshly-uploaded file there first."""
    data = await file.read()
    if len(data) > DEFAULT_LIMITS.max_media_bytes:
        raise HTTPException(status_code=413, detail="File too large")

    _, sniffed_kind = sniff(data)
    if sniffed_kind is None:
        raise HTTPException(status_code=415, detail="Unsupported file type (PDF or image only)")

    investigation_id = new_investigation_id()
    safe_name = (file.filename or "upload").replace("\\", "/").rsplit("/", 1)[-1]
    object_key = f"uploads/{investigation_id}/{safe_name}"
    await get_object_store().put(object_key, data, content_type=file.content_type)

    request = InvestigationRequest(
        investigation_id=investigation_id,
        platform=Platform.WEB,
        content_type=sniffed_kind,
        text=text,
        media=(MediaRef(kind=sniffed_kind, uri=object_key, mime_type=file.content_type, size_bytes=len(data)),),
        user_id=_owner_user_id(principal),
    )

    await _audit("investigation_created", actor=principal.principal, target_type="investigation", target_id=request.investigation_id)
    await get_investigation_repository().create_pending(
        request.investigation_id, platform=request.platform.value, content_type=request.content_type.value,
        user_id=request.user_id,
    )
    outcome = await investigate(request, media_loader=_object_store_media_loader)
    await generate_report(outcome.report, repository=get_report_repository())
    return to_web(outcome.report)


@router.get("/v1/investigations", dependencies=[Depends(require_scope(SCOPE_READ_INVESTIGATIONS))])
async def list_investigations(principal: ApiKeyPrincipal = Depends(get_principal), limit: int = 50):
    """A `user:`-principal (web login) sees only their own investigations; an
    admin-scoped service key sees everything -- same distinction
    `_owner_user_id` draws everywhere else in this router."""
    user_id = _owner_user_id(principal) if not principal.has_scope(SCOPE_ADMIN) else None
    summaries = await get_report_repository().list_summaries(limit=limit, user_id=user_id)
    return {"investigations": summaries}

@router.post("/v1/investigations/async", dependencies=[Depends(require_scope(SCOPE_ANALYZE))])
async def create_investigation_async(request: InvestigationRequest, principal: ApiKeyPrincipal = Depends(get_principal)):
    """Enqueues the investigation and returns immediately -- for callers that
    don't need the interactive-reply latency budget `/v1/investigations`
    keeps. `GET /v1/investigations/{id}` polls the result.

    No `REDIS_URL` configured is a dev-convenience fallback, not an error:
    the investigation runs inline and this returns `status: complete` right
    away, same "DISABLED means degrade, don't hard-fail" rule as the LLM
    gateway and object storage.
    """
    investigation_id = request.investigation_id
    await get_investigation_repository().create_pending(
        investigation_id, platform=request.platform.value, content_type=request.content_type.value,
        user_id=_owner_user_id(principal),
    )
    await _audit("investigation_created", actor=principal.principal, target_type="investigation", target_id=investigation_id)

    pool = await get_arq_pool()
    if pool is None:
        outcome = await investigate(request, media_loader=_object_store_media_loader)
        await generate_report(outcome.report, repository=get_report_repository())
        return {"investigation_id": investigation_id, "status": "complete"}

    await pool.enqueue_job("run_investigation", request.model_dump(mode="json"), _job_id=investigation_id)
    return {"investigation_id": investigation_id, "status": "pending"}

@router.get("/v1/investigations/{investigation_id}", dependencies=[Depends(require_scope(SCOPE_READ_INVESTIGATIONS))])
async def get_investigation(investigation_id: str, principal: ApiKeyPrincipal = Depends(get_principal)):
    await _audit("investigation_read", actor=principal.principal, target_type="investigation", target_id=investigation_id)

    report = await get_report_repository().get(investigation_id)
    if report is not None:
        return {"investigation_id": investigation_id, "status": "complete", "report": to_web(report)}

    if not await get_investigation_repository().exists(investigation_id):
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"investigation_id": investigation_id, "status": "pending"}

class ConfigRequest(BaseModel):
    hfLiteMode: Optional[bool] = None
    strictResponseMode: Optional[bool] = None

@router.post("/honeypot/config", dependencies=[Depends(require_scope(SCOPE_ADMIN))])
async def update_config(req: ConfigRequest):
    settings = get_settings()
    msg = []
    if req.hfLiteMode is not None:
        settings.HF_LITE_MODE = req.hfLiteMode
        req.hfLiteMode and hf_models.unload_models() or hf_models.load_models()
        msg.append(f"Lite Mode {'enabled' if req.hfLiteMode else 'disabled'}")
    if req.strictResponseMode is not None:
        settings.STRICT_RESPONSE_MODE = req.strictResponseMode
        msg.append(f"Strict Response Mode set to {req.strictResponseMode}")
    return {"status": "success", "message": ", ".join(msg) or "No config updated", "settings": {"HF_LITE_MODE": settings.HF_LITE_MODE, "STRICT_RESPONSE_MODE": settings.STRICT_RESPONSE_MODE}}

@router.get("/honeypot/config", dependencies=[Depends(require_scope(SCOPE_ADMIN))])
def get_config():
    settings = get_settings()
    return {"status": "success", "settings": {"HF_LITE_MODE": settings.HF_LITE_MODE, "STRICT_RESPONSE_MODE": settings.STRICT_RESPONSE_MODE}}

@router.get("/honeypot/health")
def health_check():
    return {
        "status": "ok",
        "ml_models": "loaded" if hf_models.MODELS_AVAILABLE else "loading_or_failed",
        "gemini_keys": len(gemini_pool.keys),
        "gemini_available_keys": sum(1 for k in gemini_pool.key_states.values() if k["available"]),
        "timestamp": time.time()
    }

@router.get("/honeypot/session/{session_id}", dependencies=[Depends(require_scope(SCOPE_RESEARCH_HONEYPOT))])
def get_session_details(session_id: str):
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "success", "session": session}

@router.get("/honeypot/evidence", dependencies=[Depends(require_scope(SCOPE_RESEARCH_HONEYPOT))])
async def get_evidence(principal: ApiKeyPrincipal = Depends(get_principal)):
    await _audit("evidence_read", actor=principal.principal, target_type="evidence", target_id="all")
    return {"status": "success", "data": await get_evidence_repository().get_evidence()}

@router.delete("/honeypot/session/{session_id}", dependencies=[Depends(require_scope(SCOPE_ADMIN))])
async def delete_session_data(
    session_id: str, reason: str = "owner requested deletion",
    principal: ApiKeyPrincipal = Depends(get_principal),
):
    """Owner-initiated deletion (task.md phase 7), now attributed to the real
    authenticated principal instead of the phase-7-era "api-caller"
    placeholder -- every deletion is still recorded in audit_logs regardless."""
    deleted = await get_investigation_repository().delete_for_owner(
        session_id, actor=principal.principal, reason=reason
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"status": "success", "deleted": session_id}
