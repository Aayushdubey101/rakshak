"""Behavioral security signals -- detects the *intent* to solicit a secret or
apply pretext/urgency pressure, as opposed to `RISK_SIGNALS` in `detector.py`,
which only sees isolated generic words ("confirm", "lock", "verify") with no
notion of who is asking whom to do what. Under that keyword-only model,
"we will never ask for your OTP" and "reply with your OTP" score identically
-- both just hit the same "verification" keyword bucket. This module tells
them apart with a request-verb-near-a-secret-noun pattern plus a negation
check, per-sentence, instead of point-counting.

This is a request/pretext *detector*, not a scorer: `detector.py` decides how
much a hit is worth. Evidence is the matched sentence, verbatim, so a report
can show real evidence text instead of a bare keyword.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_REQUEST_VERB = (
    r"(?:reply|respond|send|share|provide|give|forward|paste|enter|type out|"
    r"read out|tell\s+(?:us|me)|confirm(?:\s+by)?)"
)
_NEGATION_RE = re.compile(
    r"\b(?:do\s+not|don't|never|won't|will\s+not|would\s+not|should\s+not|"
    r"shouldn't|no\s+need\s+to|not\s+required\s+to|need\s+not|will\s+never)\b",
    re.IGNORECASE,
)

_GAP = r"[^.?!\n]{0,60}"


def _request_pattern(secret: str) -> re.Pattern[str]:
    return re.compile(
        rf"{_REQUEST_VERB}\b{_GAP}\b(?:{secret})\b|\b(?:{secret})\b{_GAP}{_REQUEST_VERB}\b",
        re.IGNORECASE,
    )


# Secret-noun phrases a request pattern is anchored to. Order doesn't matter
# here; priority between types is decided by the caller.
_REQUEST_SIGNAL_TERMS: dict[str, str] = {
    "MFA_CODE_REQUEST": r"(?:verification|authenticator)\s+(?:code|value)|one[- ]time\s+(?:code|password)|\bmfa\s+code\b",
    "OTP_REQUEST": r"\botp\b",
    "PASSWORD_REQUEST": r"\bpassword\b",
    "API_KEY_REQUEST": r"api[- ]?key",
    "SESSION_TOKEN_REQUEST": r"session\s+(?:token|id|cookie)",
    "AUTH_TOKEN_REQUEST": r"auth(?:entication)?\s+(?:token|code)|temporary\s+authentication\s+value|authentication\s+value",
    "SECRET_REQUEST": r"secret\s+(?:key|value|code)",
    "BANK_DETAIL_REQUEST": r"bank\s+account\s+(?:number|details)|ifsc\s+code|card\s+number|\bcvv\b",
    "PAYMENT_REQUEST": r"payment|transfer\s+(?:the\s+)?(?:money|amount|fund)",
}

_REQUEST_PATTERNS: dict[str, re.Pattern[str]] = {
    sig_type: _request_pattern(terms) for sig_type, terms in _REQUEST_SIGNAL_TERMS.items()
}

# Pretext/manipulation patterns -- no negation check, no request-verb
# requirement: these describe the *cover story*, not a request for a secret.
_PRETEXT_PATTERNS: dict[str, re.Pattern[str]] = {
    "IT_SUPPORT_PRETEXT": re.compile(
        r"\b(?:it\s+(?:support|operations|team|department)|help\s*desk|"
        r"endpoint\s+operations|technical\s+support)\b",
        re.IGNORECASE,
    ),
    "SECURITY_REVIEW_PRETEXT": re.compile(
        r"\b(?:security\s+review|access\s+review|reconciliation|"
        r"audit\s+comparison|pre-maintenance\s+review|manual[- ]review\s+queue|"
        r"compliance\s+check)\b",
        re.IGNORECASE,
    ),
    "ACCOUNT_LOCK_PRETEXT": re.compile(
        r"\baccount\s+(?:is|will\s+be|has\s+been)\s+(?:locked|blocked|suspended|disabled|frozen)\b|"
        r"\borphaned\s+(?:session|account)\b",
        re.IGNORECASE,
    ),
    "IMPERSONATION": re.compile(
        r"\b(?:this\s+is|i\s*am|i'm)\s+(?:from|with)\s+(?:the\s+)?(?:it|security|bank|support|hr)\b|"
        r"\bon\s+behalf\s+of\s+(?:the\s+)?(?:bank|it|security|management)\b",
        re.IGNORECASE,
    ),
}

_URGENCY_PATTERN = re.compile(
    r"\b(?:urgent(?:ly)?|immediately|right\s+away|as\s+soon\s+as\s+possible|asap|"
    r"before\s+(?:the\s+)?(?:window|deadline)\s+closes|closing\s+(?:the\s+|this\s+)?(?:window|queue)|"
    r"later\s+today|by\s+end\s+of\s+day|expir\w*|deadline)\b",
    re.IGNORECASE,
)

# Umbrella: any of these firing also implies the generic CREDENTIAL_REQUEST
# category from task item 4's list.
_CREDENTIAL_REQUEST_TYPES = frozenset({
    "MFA_CODE_REQUEST", "OTP_REQUEST", "PASSWORD_REQUEST", "API_KEY_REQUEST",
    "SESSION_TOKEN_REQUEST", "AUTH_TOKEN_REQUEST", "SECRET_REQUEST",
})

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.?!])\s+|\n+")


@dataclass(frozen=True)
class BehavioralSignal:
    type: str
    severity: str  # "high" | "medium"
    evidence: str  # matched sentence, verbatim


def _split_sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_SPLIT_RE.split(text) if s.strip()]


def detect(text: str) -> list[BehavioralSignal]:
    """One signal per type, first sentence that triggers it. A request
    pattern is suppressed if the same sentence also contains a negation cue
    ("do not share your password") -- context distinguishes a warning from
    an attack."""
    found: dict[str, BehavioralSignal] = {}

    for sentence in _split_sentences(text):
        negated = bool(_NEGATION_RE.search(sentence))

        for sig_type, pattern in _REQUEST_PATTERNS.items():
            if sig_type in found or negated:
                continue
            if pattern.search(sentence):
                found[sig_type] = BehavioralSignal(type=sig_type, severity="high", evidence=sentence)

        for sig_type, pattern in _PRETEXT_PATTERNS.items():
            if sig_type not in found and pattern.search(sentence):
                found[sig_type] = BehavioralSignal(type=sig_type, severity="medium", evidence=sentence)

        if "URGENCY_MANIPULATION" not in found and _URGENCY_PATTERN.search(sentence):
            found["URGENCY_MANIPULATION"] = BehavioralSignal(
                type="URGENCY_MANIPULATION", severity="medium", evidence=sentence
            )

    if "CREDENTIAL_REQUEST" not in found:
        source = next((found[t] for t in _CREDENTIAL_REQUEST_TYPES if t in found), None)
        if source is not None:
            found["CREDENTIAL_REQUEST"] = BehavioralSignal(
                type="CREDENTIAL_REQUEST", severity="high", evidence=source.evidence
            )

    return list(found.values())


def has_negated_credential_request(text: str) -> bool:
    """True if a sentence contains a credential/MFA request pattern *and* a
    negation cue -- the exact shape `detect()` intentionally suppresses as a
    request (it's a warning, not an attack: "do not send your password").
    Phase 9 item 13: this is what stops the ML layer's bare
    vocabulary-similarity opinion from overriding strong benign evidence --
    `detector.analyze()` won't let ML alone flip `isScam` True when this is
    True, even though `detect()` itself reports no positive signal here."""
    for sentence in _split_sentences(text):
        if not _NEGATION_RE.search(sentence):
            continue
        if any(pattern.search(sentence) for pattern in _REQUEST_PATTERNS.values()):
            return True
    return False
