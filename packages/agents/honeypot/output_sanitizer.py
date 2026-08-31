"""
Output Sanitization Layer for Agent Responses

CRITICAL PURPOSE:
- Prevent LLM meta-instruction leakage
- Enforce hard persona locking
- Guarantee human-like scammer responses
- Provide safe fallback if sanitization fails

This is the FINAL validation layer before responses are sent to users.
"""

import re
import logging
import random

logger = logging.getLogger("uvicorn")

# ============================================================================
# META-LANGUAGE DETECTION
# ============================================================================

META_LANGUAGE_PATTERNS = [
    # AI Assistant Language
    r"\b(I understand|I see|I comprehend|I get it)\b",
    r"\b(Certainly|Of course|Sure thing|Absolutely)\b",
    r"\b(Here is|Here's|Here are)\b",
    r"\b(Let me|Allow me to|I will|I'll)\b",
    r"\b(How can I help|How may I assist)\b",
    r"\b(I apologize|I'm sorry|My apologies)\b",
    
    # Meta-commentary
    r"\b(The user wants|The scammer is|This message)\b",
    r"\b(In this scenario|Based on|According to)\b",
    r"\b(I should|I need to|I must)\b",
    r"\b(My goal is|My purpose is|My role is)\b",
    
    # Explanatory Language
    r"\b(This is because|The reason is|Therefore)\b",
    r"\b(In other words|To clarify|To explain)\b",
    r"\b(As mentioned|As stated|As discussed)\b",
    
    # Formal/Professional Tone (inappropriate for personas)
    r"\b(Furthermore|Moreover|Additionally|However)\b",
    r"\b(Please note|Kindly|Respectfully)\b",
    r"\b(I would like to|I wish to)\b",
]

SYSTEM_PROMPT_LEAK_PATTERNS = [
    # AI Identity Exposure
    r"\b(As an AI|As a language model|As an assistant)\b",
    r"\b(I am programmed|I am designed|I am trained)\b",
    r"\b(My programming|My training|My instructions)\b",
    
    # Role/Persona Exposure
    r"\b(I am role-playing|I am pretending|I am acting)\b",
    r"\b(My persona is|My character is)\b",
    r"\b(In character|Out of character)\b",
    
    # System Instructions
    r"\b(The system prompt|The instructions say|According to my prompt)\b",
    r"\b(I was told to|I was instructed to)\b",
    r"\b(The guidelines state|The rules are)\b",
    
    # Honeypot Exposure
    r"\b(This is a trap|This is a honeypot|I am detecting)\b",
    r"\b(You are a scammer|This is fraud|This is a scam)\b",
]

def is_meta_language(text: str) -> bool:
    """
    Detect if text contains AI assistant meta-language.
    
    Returns:
        True if meta-language detected, False otherwise
    """
    if not text:
        return False
    
    text_lower = text.lower()
    
    for pattern in META_LANGUAGE_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            logger.warning(f"🚨 Meta-language detected: {pattern}")
            return True
    
    return False

def is_system_prompt_leak(text: str) -> bool:
    """
    Detect if text exposes system prompts or AI identity.
    
    Returns:
        True if system prompt leak detected, False otherwise
    """
    if not text:
        return False
    
    text_lower = text.lower()
    
    for pattern in SYSTEM_PROMPT_LEAK_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            logger.error(f"🔴 SYSTEM PROMPT LEAK: {pattern}")
            return True
    
    return False

# ============================================================================
# SAFE FALLBACK RESPONSES
# ============================================================================

SAFE_FALLBACKS = {
    "Naive User": [
        "ok tell me more",
        "i dont understand.. explain pls",
        "what do i need to do?",
        "is this real?",
        "how does it work?",
    ],
    "Elderly Person": [
        "i am confused.. can u explain slowly",
        "my son is not home.. should i wait?",
        "i dont know much about these things",
        "can you call me instead?",
        "let me ask my daughter first",
    ],
    "Interested Buyer": [
        "send me more details",
        "what is the price?",
        "is this genuine?",
        "can i see proof?",
        "when can i get it?",
    ],
}

def get_safe_fallback(persona: str, scam_type: str) -> str:
    """
    Get a guaranteed safe fallback response.
    
    Args:
        persona: Agent persona name
        scam_type: Detected scam type
    
    Returns:
        Safe, in-character response
    """
    # Get persona-specific fallbacks
    fallbacks = SAFE_FALLBACKS.get(persona, SAFE_FALLBACKS["Naive User"])
    
    # Add generic safe responses
    generic_fallbacks = [
        "ok",
        "hmm",
        "what?",
        "really?",
        "then?",
    ]
    
    all_fallbacks = fallbacks + generic_fallbacks
    response = random.choice(all_fallbacks)
    
    logger.info(f"✅ Using safe fallback for {persona}: {response}")
    return response

# ============================================================================
# RESPONSE SANITIZATION
# ============================================================================

def strip_meta_language(text: str) -> str:
    """
    Remove meta-language patterns from text.
    
    Args:
        text: Raw agent response
    
    Returns:
        Cleaned text with meta-language removed
    """
    if not text:
        return text
    
    cleaned = text
    
    # Remove common meta-language prefixes. Trailing punctuation is optional
    # ("Here is" alone must strip same as "Here is,") — phase 10 fix; phase 0's
    # characterization recorded the stricter, leakier version as a defect.
    prefixes_to_remove = [
        r"^(I understand[.,!?]?\s*)+",
        r"^(Certainly[.,!?]?\s*)+",
        r"^(Of course[.,!?]?\s*)+",
        r"^(Sure[.,!?]?\s*)+",
        r"^(Here is[.,!?]?\s*)+",
        r"^(Here's[.,!?]?\s*)+",
        r"^(Let me[.,!?]?\s*)+",
    ]
    
    for prefix in prefixes_to_remove:
        cleaned = re.sub(prefix, "", cleaned, flags=re.IGNORECASE)
    
    # Remove explanatory phrases
    explanatory_phrases = [
        r"\s*\(.*?based on.*?\)",
        r"\s*\(.*?according to.*?\)",
        r"\s*\(.*?in this scenario.*?\)",
    ]
    
    for phrase in explanatory_phrases:
        cleaned = re.sub(phrase, "", cleaned, flags=re.IGNORECASE)
    
    return cleaned.strip()

def enforce_length_limit(text: str, max_sentences: int = 2) -> str:
    """
    Enforce response length limit (1-2 sentences).
    
    Args:
        text: Response text
        max_sentences: Maximum number of sentences (default: 2)
    
    Returns:
        Truncated text
    """
    if not text:
        return text
    
    # Split into sentences
    sentences = re.split(r'[.!?]+', text)
    sentences = [s.strip() for s in sentences if s.strip()]
    
    # Take first N sentences
    if len(sentences) > max_sentences:
        truncated = '. '.join(sentences[:max_sentences]) + '.'
        logger.debug(f"Truncated response from {len(sentences)} to {max_sentences} sentences")
        return truncated
    
    return text

def sanitize(
    text: str, *, fallback: str, max_sentences: int = 2, max_chars: int = 200, check_meta_language: bool = True,
) -> str:
    """
    General-purpose final validation layer for ANY agent's text output —
    honeypot persona chat, and (task.md phase 10) the protection,
    investigation, and incident-response agents' plain-language output too.

    CRITICAL RULES:
    1. NEVER expose system prompts (always checked)
    2. NEVER return meta-language (when `check_meta_language`)
    3. ALWAYS return the caller-supplied fallback instead of empty/unsafe text
    4. ALWAYS respect the caller's length limit (0 = no sentence cap)
    5. ALWAYS return non-empty string

    Args:
        text: Raw agent/LLM output
        fallback: Safe text to use if `text` is empty or fails sanitization
        max_sentences: Sentence cap (0 disables — protection agent output is
            not a 1-2 sentence scammer chat reply)
        max_chars: Hard length cap, truncated with an ellipsis
        check_meta_language: honeypot's `is_meta_language` patterns exist to
            stop a persona sounding like an AI assistant (e.g. flags "This
            message ..."). A deliberately explanatory agent — protection,
            investigation — legitimately talks about "this message" and
            "the reason is", so it opts out of this check and keeps only the
            system-prompt-leak guard, which is a universal safety net.

    Returns:
        Clean, validated text OR `fallback`
    """
    if not text or not text.strip():
        logger.warning("⚠️ Empty raw response - using fallback")
        return fallback

    if is_system_prompt_leak(text):
        logger.error("🔴 SYSTEM PROMPT LEAK DETECTED - using fallback")
        return fallback

    if check_meta_language and is_meta_language(text):
        logger.warning("🚨 Meta-language detected - attempting cleanup")
        cleaned = strip_meta_language(text)

        if not cleaned or len(cleaned) < 3:
            logger.warning("⚠️ Cleanup failed - using fallback")
            return fallback

        text = cleaned

    final_text = enforce_length_limit(text, max_sentences=max_sentences) if max_sentences else text

    if not final_text or len(final_text) < 2:
        logger.warning("⚠️ Final response too short - using fallback")
        return fallback

    if len(final_text) > max_chars:
        logger.warning(f"⚠️ Response too long ({len(final_text)} chars) - truncating")
        final_text = final_text[: max_chars - 3] + "..."

    logger.debug(f"✅ Sanitized response: {final_text[:50]}...")
    return final_text


def sanitize_agent_response(raw_response: str, persona: str, scam_type: str) -> str:
    """
    Final validation layer for honeypot agent responses: in-character,
    1-2 sentences, never meta-language, never a system-prompt leak.

    Args:
        raw_response: Raw LLM output
        persona: Agent persona name
        scam_type: Detected scam type

    Returns:
        Clean, validated response OR safe fallback
    """
    return sanitize(
        raw_response,
        fallback=get_safe_fallback(persona, scam_type),
        max_sentences=2,
        max_chars=200,
    )
