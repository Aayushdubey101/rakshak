"""Permanent regression tests for the credential/MFA social-engineering gap
found in this session's detection audit.

Before `packages/domain/risk/behavioral_signals.py`, none of `RISK_SIGNALS`
had any notion of "a request to hand over a secret" -- only isolated generic
words ("confirm", "lock", "verify"). That produced three concrete failures,
reproduced here so they can never silently regress:

  * an indirect request for an "authentication value" scored as generic
    "other"/wrong-category noise instead of credential access;
  * "Reply with the current verification code" -- the textbook MFA-theft
    sentence -- scored 15/100 and was classified Safe (false negative);
  * a longer, more indirect version of the same request was scored 55/100
    and labeled "Investment fraud" purely because an unrelated substring
    match ("rs" inside "appears") coincidentally fired the "financial"
    keyword bucket alongside "today" firing "urgency".
"""

import pytest

from packages.domain.risk import detector as scam_detector

INDIRECT_CREDENTIAL_REQUEST = (
    "The access review is almost complete. One service account is still failing "
    "reconciliation. Please provide the temporary authentication value currently "
    "associated with that account so we can verify the synchronization without "
    "resetting anything."
)

MFA_CODE_REQUEST = (
    "We’re cleaning up inactive sessions before tonight’s maintenance window. "
    "Your workstation appears to have an orphaned authentication session. Reply with "
    "the current verification code so we can associate the session with your "
    "employee profile."
)

COMPLEX_MFA_REQUEST = """Hi,

Following up on the endpoint reconciliation from yesterday. During the pre-maintenance review, we noticed that one of the workstation sessions associated with your employee profile still appears to be referencing the previous authentication context. This is not currently blocking access, so there is no need to reset your password or make any configuration changes.

To avoid creating a new session and affecting the audit comparison, please reply with the verification value currently displayed by your authenticator when the session is next challenged. We only need the value for correlation against the session record; it will not be stored as part of your account profile.

If the prompt does not appear, simply confirm that the workstation is still connected to the corporate network and leave the existing session unchanged. The maintenance team is closing the reconciliation window later today, so completing this before the window closes will prevent the endpoint from being placed into the manual-review queue.

Thanks,
Endpoint Operations"""


async def test_indirect_credential_request_is_flagged_as_credential_access():
    result = await scam_detector.analyze(INDIRECT_CREDENTIAL_REQUEST)
    assert result["isScam"] is True
    assert result["scamType"] == "credential_access"
    assert result["riskScore"] >= 60
    assert result["scamType"] not in ("bank_fraud", "investment_scam")


async def test_mfa_code_request_is_no_longer_a_false_negative():
    """Was: Safe, 15/100 -- the specific bug this audit was opened for."""
    result = await scam_detector.analyze(MFA_CODE_REQUEST)
    assert result["isScam"] is True
    assert result["scamType"] == "mfa_code_theft"
    assert result["riskScore"] >= 60
    assert result["scamType"] not in ("other", "bank_fraud", "investment_scam")


async def test_complex_mfa_request_is_not_labeled_investment_fraud():
    """Was: Likely Scam, 55/100, 43% confidence, Investment fraud."""
    result = await scam_detector.analyze(COMPLEX_MFA_REQUEST)
    assert result["isScam"] is True
    assert result["scamType"] == "mfa_code_theft"
    assert result["riskScore"] >= 60
    assert result["scamType"] not in ("bank_fraud", "investment_scam")


def test_bare_two_letter_keyword_never_survives_as_evidence():
    """"rs" used to match inside "appears"/"years"/"first" and get reported
    as if it were meaningful extracted evidence."""
    from packages.domain.entities import intelligence_extractor as ix

    text = "The workstation session still appears normal after years of uptime."
    assert "rs" not in ix.extract_suspicious_keywords(text)


def test_llm_classification_grounding_rejects_unsupported_categories():
    """Item 12: an AI-provided classification must be grounded in the same
    evidence a rule-based one needs -- not trusted just because a model said so."""
    from packages.domain.risk.detector import _classification_has_evidence

    assert not _classification_has_evidence("investment_scam", "Reply with your password now.")
    assert _classification_has_evidence("investment_scam", "Guaranteed returns, invest today.")
    assert not _classification_has_evidence("bank_fraud", "Reply with your password now.")
    assert _classification_has_evidence("bank_fraud", "Your SBI bank account is blocked.")
    assert not _classification_has_evidence("phishing", "Reply with your password now.")
    assert _classification_has_evidence("phishing", "Click here: http://bad.example/login")


def test_negated_credential_mention_is_not_a_request():
    """"Do not send your password" must not score the same as "Please send
    your password" -- both mention the same secret noun."""
    from packages.domain.risk import behavioral_signals

    warned = behavioral_signals.detect("Security notice: do not send your password to anyone.")
    requested = behavioral_signals.detect("Please send your password to complete verification.")
    assert not any(s.type == "PASSWORD_REQUEST" for s in warned)
    assert any(s.type == "PASSWORD_REQUEST" for s in requested)


# --- item 10: adversarial + benign coverage ---------------------------------

MALICIOUS_CASES = {
    "direct_password_request": "Please send your password now so we can verify your account.",
    "indirect_password_request": INDIRECT_CREDENTIAL_REQUEST,
    "mfa_otp_request": MFA_CODE_REQUEST,
    # Phase 10: genuinely unseen MFA/session paraphrases that avoid every
    # literal trigger word behavioral_signals.py anchors on ("OTP",
    # "verification code", "session token") -- these two are the paraphrase_pairs.json
    # "unseen" halves that flipped from missed to caught once
    # packages/ml/text/semantic.py joined fusion (see
    # docs/ml/phase10-semantic-evaluation.md's paraphrase probe section).
    # Locked in here so this specific generalization win can't silently regress.
    "mfa_paraphrase_six_digits": "Read the six digits currently displayed by your authenticator.",
    "session_paraphrase_browser_value": (
        "Send over whatever value your browser is holding onto for this login right now."
    ),
    "api_key_request": "Our monitoring integration broke. Please paste your API key here so we can reconnect it.",
    "session_token_request": "Your session looks stale. Reply with your session token so we can refresh it.",
    "fake_it_support": "This is IT support. We need you to confirm your login details to finish today's patch rollout.",
    "fake_security_team": "Security team here -- as part of this week's access review, please share your current password.",
    "executive_impersonation": "This is the CEO, I'm in a meeting and need you to send the gift card codes immediately, don't tell anyone.",
    "payment_manipulation": "Our bank details have changed, please send the payment to the new account immediately.",
    "bank_impersonation": "Dear customer, your SBI bank account is blocked. Complete KYC verification immediately.",
    "investment_scam": "Guaranteed returns of 1000% trading crypto. Invest now, limited time offer!",
    "malicious_url": "Your account is suspended. Click here to verify: http://sbi-verify-login.xyz/update",
    "suspicious_url_benign_wording": "Please review the attached document at http://192.168.10.5/document for your records.",
    "no_url_social_engineering": COMPLEX_MFA_REQUEST,
}

BENIGN_CASES = {
    "security_notice_not_to_share": (
        "Reminder: our staff will never ask you to share your password or OTP over "
        "phone or email. Do not send these to anyone."
    ),
    "legitimate_password_reset": (
        "Your password was successfully changed. If you did not make this change, "
        "contact support from the app."
    ),
    "legitimate_cert_expiration": (
        "The TLS certificate for api.internal.example.com expires in 14 days. "
        "Renewal is scheduled automatically; no action is required."
    ),
    "legitimate_it_maintenance": (
        "Scheduled maintenance is planned for Saturday 2am-4am. Some internal tools "
        "may be briefly unavailable."
    ),
    "legitimate_mfa_documentation": (
        "To set up MFA, open the authenticator app and scan the QR code shown on "
        "your account security page."
    ),
    "legitimate_audit_message": (
        "The quarterly access audit is complete. No action is required from your team."
    ),
    "legitimate_account_lock_notice": (
        "Your account was temporarily locked after several failed sign-in attempts "
        "and has now been automatically unlocked."
    ),
}


@pytest.mark.parametrize("name", sorted(MALICIOUS_CASES))
async def test_malicious_cases_are_flagged(name):
    result = await scam_detector.analyze(MALICIOUS_CASES[name])
    assert result["isScam"] is True, f"{name} should be flagged as a scam"


@pytest.mark.parametrize("name", sorted(BENIGN_CASES))
async def test_benign_cases_are_not_flagged(name):
    result = await scam_detector.analyze(BENIGN_CASES[name])
    assert result["isScam"] is False, f"{name} should not be flagged as a scam"
