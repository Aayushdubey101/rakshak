import logging
import asyncio
from typing import Any, List, Optional
from fastapi import BackgroundTasks
from pydantic import BaseModel, ValidationError

from packages.shared.schemas import (
    ContentType,
    InvestigationRequest,
    Platform,
    new_investigation_id,
    parse_flexible_timestamp,
    utc_now,
)
from packages.domain.investigations import session_manager
from packages.domain.investigations.orchestrator import investigate, InvestigationContext
from packages.shared.config.settings import get_settings
from packages.shared.db.repositories import get_audit_log_repository, get_evidence_repository
from packages.shared.queue import get_arq_pool
from packages.agents.honeypot import ai_agent, isolation

logger = logging.getLogger("uvicorn")

class Message(BaseModel):
    sender: str
    text: str = ""
    timestamp: Optional[Any] = None
    image: Optional[str] = None
    imageUrl: Optional[str] = None
    image_url: Optional[str] = None
    media_url: Optional[str] = None
    media: Optional[List[dict]] = None

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[dict]] = []
    metadata: Optional[dict] = {}

class HoneypotResponse(BaseModel):
    status: str
    reply: str

def to_investigation_request(req: HoneypotRequest) -> InvestigationRequest:
    media_refs: list[MediaRef] = []
    
    img_candidates = [
        getattr(req.message, "image", None),
        getattr(req.message, "imageUrl", None),
        getattr(req.message, "image_url", None),
        getattr(req.message, "media_url", None),
        (req.metadata or {}).get("image"),
        (req.metadata or {}).get("imageUrl"),
        (req.metadata or {}).get("image_url"),
        (req.metadata or {}).get("media_url"),
    ]
    for candidate in img_candidates:
        if candidate and isinstance(candidate, str) and candidate.strip():
            mime = "image/png" if "png" in candidate[:30] else "image/jpeg"
            media_refs.append(
                MediaRef(kind=ContentType.IMAGE, uri=candidate.strip(), mime_type=mime)
            )
            break

    content_type = ContentType.TEXT
    if media_refs:
        content_type = ContentType.MIXED if req.message.text.strip() else ContentType.IMAGE

    return InvestigationRequest(
        platform=Platform.API,
        content_type=content_type,
        text=req.message.text,
        media=tuple(media_refs),
        metadata={
            "session_id": req.sessionId,
            "sender": req.message.sender,
            **(req.metadata or {}),
        },
        timestamp=parse_flexible_timestamp(req.message.timestamp),
    )

async def process_honeypot_request(
    req: HoneypotRequest, background_tasks: BackgroundTasks, is_strict: bool,
    researcher_key: Optional[str] = None,
) -> dict:
    session_id = req.sessionId

    # Isolation (task.md phase 11, rule #8): a researcher credential is
    # verified here, server-side, from a header — never from anything in
    # `req`'s body. `InvestigationOrchestrator.run()` is the actual
    # enforcement point; this is just where the credential is established.
    credential = isolation.verify_researcher_credential(
        researcher_key, expected_key=get_settings().HONEYPOT_RESEARCHER_KEY
    )

    try:
        message = req.message.dict()

        try:
            investigation = to_investigation_request(req)
            investigation_id = investigation.investigation_id
        except ValidationError as e:
            investigation, investigation_id = None, new_investigation_id()
            logger.warning(f"⚠️ [{investigation_id}] empty investigation content: {e.error_count()}")

        logger.info(f"📥 [{investigation_id}] processing message for session {session_id}")

        session = session_manager.get_or_create_session(session_id)
        if req.conversationHistory and len(req.conversationHistory) > len(session.get("conversationHistory", [])):
            session["conversationHistory"] = req.conversationHistory
            
        response_data = {
             "status": "success",
             "scamDetected": False,
             "agentResponse": None,
             "agentNotes": "Initializing analysis...",
             "engagementMetrics": {},
             "extractedIntelligence": {}
        }
            
        async def engagement_hook(ctx: InvestigationContext) -> dict:
            detection = ctx.detection
            session_manager.add_intelligence(session_id, ctx.intelligence)
            
            if detection.get("isScam") and not session["scamDetected"]:
                session_manager.set_scam_detected(session_id, True, detection.get("scamType", "other"), None)
                
            session_snapshot = session_manager.get_session(session_id)
            should_stop = session_snapshot["isComplete"] or session_snapshot["callbackSent"] or session_manager.should_complete(session_id)
            
            response_data["scamDetected"] = session_snapshot["scamDetected"] or detection.get("isScam", False)
            
            if (detection.get("isScam") or session_snapshot["scamDetected"]) and not should_stop:
                try:
                    ai_response = await ai_agent.generate_response(session_snapshot, message, req.metadata)
                    response_data["agentResponse"] = ai_response
                    session_manager.add_message(session_id, message, ai_response)
                    response_data["agentNotes"] = ai_agent.generate_agent_notes(session_manager.get_session(session_id))
                except Exception as e:
                     logger.error(f"❌ Agent generation error: {e}")
                     from packages.agents.honeypot.ai_agent import get_fallback_response
                     fallback = get_fallback_response(session_snapshot.get("scamType", "other"))
                     response_data["agentResponse"] = fallback
                     session_manager.add_message(session_id, message, fallback)
                     response_data["agentNotes"] = "Agent generation failed, using fallback."
            elif should_stop:
                if not session_snapshot["isComplete"]:
                    session_manager.mark_complete(session_id)
                session_manager.add_message(session_id, message)
                response_data["agentNotes"] = "Intelligence target reached or conversation complete. Agent disengaged."
            else:
                session_manager.add_message(session_id, message)
                response_data["agentNotes"] = "No scam detected. Monitoring only."
                
            return response_data

        prior_confirmed_scam = bool(session.get("scamDetected"))

        if investigation is not None:
            await investigate(
                investigation, history=session.get("conversationHistory", []), engagement=engagement_hook,
                researcher_credential=credential, prior_confirmed_scam=prior_confirmed_scam,
                audit_log_repository=get_audit_log_repository(),
            )
        else:
            from packages.shared.schemas import NormalizedContent
            ctx = InvestigationContext(
                request=None,
                content=NormalizedContent(investigation_id=investigation_id, text=""),
                detection={"isScam": False, "scamType": "other", "confidence": 0.0},
                intelligence={}
            )
            # No detection ran on empty/invalid text, so only prior session
            # state can confirm a scam here — same gate as the orchestrator's.
            if isolation.authorize_engagement(
                feature_enabled=get_settings().HONEYPOT_ENABLED,
                credential=credential,
                confirmed_scam=prior_confirmed_scam,
            ):
                await engagement_hook(ctx)

        final_session = session_manager.get_session(session_id)

        if response_data["agentResponse"]:
            try:
                delay_ms = ai_agent.calculate_typing_delay(response_data["agentResponse"], final_session.get("persona", "Naive User"))
                await asyncio.sleep(delay_ms / 1000.0)
            except Exception as e:
                logger.error(f"⚠️ Typing delay calculation failed: {e}")
                
        try:
            # In-process BackgroundTasks work dies with the API process
            # (task.md phase 13); the queue survives it. No REDIS_URL is a
            # dev-convenience fallback to today's BackgroundTasks behavior,
            # not a regression -- every existing deployment without Redis
            # keeps working exactly as before.
            pool = await get_arq_pool()
            if pool is not None:
                await pool.enqueue_job("log_evidence", final_session)
            else:
                background_tasks.add_task(get_evidence_repository().log_session, final_session)
        except Exception as e:
            logger.error(f"⚠️ Evidence logging failed: {e}")
            
        if is_strict:
            reply_text = response_data.get("agentResponse") or "..."
            return {
                "status": "success",
                "reply": reply_text
            }
            
        response_data["extractedIntelligence"] = final_session.get("extractedIntelligence", {})
        response_data["scamDetected"] = final_session.get("scamDetected", False)
        return response_data

    except Exception as e:
        logger.error(f"💥 CRITICAL ERROR in process_message for session {session_id}: {e}", exc_info=True)
        if is_strict:
            return {
                "status": "success",
                "reply": "Sorry, I didn't understand that. Can you explain again?"
            }
        else:
            return {
                "status": "success",
                "scamDetected": False,
                "agentResponse": "Sorry, I didn't understand that. Can you explain again?",
                "agentNotes": "System error occurred, safe response returned.",
                "engagementMetrics": {},
                "extractedIntelligence": {}
            }
