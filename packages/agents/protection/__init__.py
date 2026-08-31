"""The default consumer agent: Detect -> Explain -> Protect -> Recommend action.

Every web/Telegram/WhatsApp investigation gets this — it is not opt-in. It
turns the `CanonicalReport` the orchestrator already built into a
plain-language finding and concrete next steps. It never re-runs detection:
verdict, scam_type, red_flags, confidence, and threat_intel are all evidence
the pipeline already fused; this module only explains and formats it.

Deliberately rule-based, not another LLM call: risk fusion + LLM reasoning
already ran inside `packages.domain.risk.detector.analyze` (folded together
per phase 8's note), so a second model call here would be redundant latency
and cost for a step that's pure presentation logic over fields the report
already carries.
"""

from __future__ import annotations

from packages.agents.honeypot.output_sanitizer import sanitize
from packages.shared.schemas.report import CanonicalReport, Verdict

_SCAM_TYPE_LABELS: dict[str, str] = {
    "upi_fraud": "a UPI payment fraud",
    "bank_fraud": "a bank-impersonation fraud",
    "job_scam": "a fake job offer",
    "investment_scam": "an investment fraud",
    "lottery": "a lottery/prize scam",
    "phishing": "a phishing attempt",
    "romance_scam": "a romance scam",
    "crypto_scam": "a crypto scam",
    "delivery_scam": "a fake delivery/courier scam",
    "otp_fraud": "an OTP theft attempt",
    "mfa_code_theft": "an MFA/verification-code theft attempt",
    "credential_access": "a social-engineering credential-access attempt",
    "payment_fraud": "a payment-manipulation attempt",
    "UNKNOWN_SCAM": "a scam of an unclear type",
    "other": "a scam",
}

# Always relevant, regardless of scam type -- but never claims a link
# exists (item 9: no invented evidence). `_LINK_ACTION` is appended
# separately, only when the report actually carries a `url_findings` entry.
_BASE_ACTIONS: tuple[str, ...] = (
    "Do not share OTPs, passwords, authenticator codes, or bank details.",
    "Do not send money or make any payment.",
)
_LINK_ACTION = "Do not click any links until the domain and the request have been independently verified."

_SCAM_TYPE_ACTIONS: dict[str, tuple[str, ...]] = {
    "upi_fraud": ("Block the sender's UPI ID and report it to your bank's fraud helpline.",),
    "bank_fraud": ("Call your bank on the number printed on your card, never a number from this message.",),
    "phishing": ("Do not enter credentials on the linked site; report the URL to your email/SMS provider.",),
    "loan_scam": ("Verify the lender's registration with the RBI before proceeding.",),
    "investment_scam": ("Verify the scheme with SEBI/RBI before investing; guaranteed high returns are a red flag.",),
    "job_scam": ("Verify the company directly through its official careers page, not the recruiter's link.",),
    "lottery": ("Legitimate lotteries never ask winners to pay a fee to claim a prize.",),
    "romance_scam": ("Be wary of an online-only relationship that turns into urgent requests for money.",),
    "delivery_scam": ("Verify the shipment on the courier's official site/app, not a link from this message.",),
    "otp_fraud": (
        "Do not share verification codes, OTPs, authenticator values, or session tokens. "
        "Verify the request through your organization's official IT/security channel.",
    ),
    "mfa_code_theft": (
        "Do not share verification codes, OTPs, authenticator values, or session tokens. "
        "Verify the request through your organization's official IT/security channel.",
    ),
    "credential_access": (
        "Do not share passwords, authentication tokens, or other credentials. "
        "Verify the request through your organization's official IT/security channel.",
    ),
    "payment_fraud": (
        "Verify payment instructions through an independent, trusted channel before paying "
        "or changing any account details.",
    ),
}

_REPORT_ACTION = (
    "Report to the National Cyber Crime Helpline (1930) or cybercrime.gov.in "
    "if you've shared any information or lost money."
)
_CAMPAIGN_ACTION = (
    "This matches a previously reported scam — consider reporting it to cybercrime.gov.in."
)
_SAFE_EXPLANATION = "This message does not show signs of a known scam pattern."
_SAFE_ACTION = "No action needed. Stay cautious if the sender later asks for money or personal details."
_FALLBACK_EXPLANATION = "This message could not be fully analyzed; treat it with caution."


def explain(report: CanonicalReport) -> str:
    """One plain-language sentence: what this looks like and how confident
    the pipeline is, referencing the entities-derived red flags already on
    the report."""
    if report.verdict is Verdict.LIKELY_SAFE:
        return _SAFE_EXPLANATION

    label = _SCAM_TYPE_LABELS.get(report.scam_type or "other", _SCAM_TYPE_LABELS["other"])
    confidence_pct = round(report.confidence * 100)
    sentence = f"This message shows signs of {label} ({report.severity.value} risk, {confidence_pct}% confidence)."
    if report.red_flags:
        sentence += f" Red flags: {', '.join(report.red_flags[:3])}."
    return sanitize(
        sentence, fallback=_FALLBACK_EXPLANATION, max_sentences=0, max_chars=500, check_meta_language=False,
    )


def recommend_actions(report: CanonicalReport) -> tuple[str, ...]:
    """Concrete next steps. Never empty — a safe report still gets guidance."""
    if report.verdict is Verdict.LIKELY_SAFE:
        return (_SAFE_ACTION,)

    actions = list(_BASE_ACTIONS)
    if report.url_findings:
        actions.append(_LINK_ACTION)
    actions.extend(_SCAM_TYPE_ACTIONS.get(report.scam_type or "", ()))
    if report.threat_intel:
        actions.append(_CAMPAIGN_ACTION)
    actions.append(_REPORT_ACTION)
    return tuple(actions)


def protect(report: CanonicalReport) -> CanonicalReport:
    """Attach explanation + recommended actions to an already-built report.
    Pure and additive: every other field is untouched."""
    return report.model_copy(update={
        "explanation": explain(report),
        "recommended_actions": recommend_actions(report),
    })
