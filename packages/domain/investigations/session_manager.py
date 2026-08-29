import time
import logging

from packages.shared.redis_client import get_redis_client
from packages.shared.session_store import SessionStore

logger = logging.getLogger("uvicorn")

# In-memory dict when REDIS_URL is unset (unchanged default behavior);
# Redis-backed when configured, so two API processes share sessions.
sessions = SessionStore(get_redis_client())

def create_session(session_id: str) -> dict:
    return {
        "sessionId": session_id,
        "scamDetected": False,
        "scamType": None,

        # 🔹 NEW (ML metadata)
        "mlScamConfidence": None,
        "mlScamLabel": None,
        "sentiment": None,
        "language": None,

        "persona": None,
        "conversationHistory": [],
        "extractedIntelligence": {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        },
        "startTime": time.time(),
        "messageCount": 0,
        "isComplete": False,
        "callbackSent": False
    }

def get_or_create_session(session_id: str) -> dict:
    if session_id not in sessions:
        sessions[session_id] = create_session(session_id)
        logger.info(f"New session created: {session_id}")
    return sessions[session_id]

def add_message(session_id: str, message: dict, agent_response: str = None):
    session = sessions.get(session_id)
    if not session:
        return

    session["conversationHistory"].append({
        "sender": message["sender"],
        "text": message["text"],
        "timestamp": message.get("timestamp") or time.time()
    })
    session["messageCount"] += 1

    if agent_response:
        session["conversationHistory"].append({
            "sender": "agent",
            "text": agent_response,
            "timestamp": time.time()
        })
        session["messageCount"] += 1

def set_scam_detected(
    session_id: str,
    is_scam: bool,
    scam_type: str,
    persona: str = None,

    # 🔹 NEW (OPTIONAL ML SIGNALS)
    ml_confidence: float = None,
    ml_label: str = None,
    sentiment: str = None,
    language: str = None
):
    session = sessions.get(session_id)
    if session:
        session["scamDetected"] = is_scam
        session["scamType"] = scam_type

        # 🔹 STORE ML SIGNALS
        if ml_confidence is not None:
            session["mlScamConfidence"] = ml_confidence
        if ml_label is not None:
            session["mlScamLabel"] = ml_label
        if sentiment is not None:
            session["sentiment"] = sentiment
        if language is not None:
            session["language"] = language

        if persona:
            session["persona"] = persona

def add_intelligence(session_id: str, new_intel: dict):
    session = sessions.get(session_id)
    if not session:
        return

    current_intel = session["extractedIntelligence"]
    for key, values in new_intel.items():
        if key in current_intel and isinstance(values, list):
            existing = set(current_intel[key])
            existing.update(values)
            current_intel[key] = list(existing)

def get_engagement_duration(session_id: str) -> int:
    session = sessions.get(session_id)
    if not session:
        return 0
    return int(time.time() - session["startTime"])

def get_session(session_id: str) -> dict:
    session = sessions.get(session_id)
    if session:
        import copy
        return copy.deepcopy(session)
    return None

def mark_complete(session_id: str):
    session = sessions.get(session_id)
    if session:
        session["isComplete"] = True

def mark_callback_sent(session_id: str):
    session = sessions.get(session_id)
    if session:
        session["callbackSent"] = True

def get_intelligence_score(intel: dict) -> int:
    score = 0
    score += len(intel.get("upiIds", [])) * 30
    score += len(intel.get("phoneNumbers", [])) * 20
    score += len(intel.get("bankAccounts", [])) * 25
    score += len(intel.get("phishingLinks", [])) * 15
    return score

def detect_disengagement(session: dict) -> bool:
    history = session.get("conversationHistory", [])
    if not history:
        return False

    last_msg = history[-1]
    if last_msg["sender"] != "agent" and last_msg.get("text") and len(last_msg["text"].split()) < 3:
        text_lower = last_msg["text"].lower()
        if any(w in text_lower for w in ["bye", "fuck", "stop", "scam", "fake"]):
            return True

    return False

def should_complete(session_id: str) -> bool:
    session = sessions.get(session_id)
    if not session or session["isComplete"] or session["callbackSent"]:
        return True

    message_count = session["messageCount"]
    turns = message_count // 2

    intel = session["extractedIntelligence"]
    score = get_intelligence_score(intel)

    if turns < 8:
        if detect_disengagement(session):
            logger.info(f"Session {session_id} ending early due to disengagement.")
            return True
        return False

    if turns >= 25:
        logger.info(f"Session {session_id} reached max turns (25).")
        return True

    if score < 50 and turns < 15:
        return False

    if score >= 80:
        logger.info(f"Session {session_id} ending with high intel score ({score}).")
        return True

    if score >= 50 and turns >= 12:
        logger.info(f"Session {session_id} ending with good intel score ({score}).")
        return True

    if detect_disengagement(session):
        logger.info(f"Session {session_id} ending due to disengagement.")
        return True

    return False
