"""Golden output for scam_detector. Records behavior as of phase 9.

Values were captured by running the current code, not chosen. A failure here
means detection changed — decide whether that change was intended before
editing the expectations.

Environment (set in tests/conftest.py): lite mode, so detect_spam/detect_language
return the neutral fallbacks (no ML signal produced) and no Gemini keys, so
ai_based_detection returns None — fusion runs over the pattern signal plus
the supervised classifier signal (which runs unconditionally, lite mode or
not).

Phase 8 changed `confidence` (only): fusion now renormalizes over signals
that actually ran instead of averaging in an absent ML/LLM signal as zero.

Phase 9 changed `confidence` again (the supervised classifier was retrained
on ml-models/evaluation/dev_train_set_v2.json -- 1321 examples, up from 90 --
with a new word+char-ngram TF-IDF feature set and a threshold raised from 0.5
to 0.65, see packages/ml/model_registry.py) and fixed one long-standing
mislabel: `bank_fraud` now resolves to `bank_fraud` instead of `UNKNOWN_SCAM`
-- the rules layer still can't name it directly (no literal "bank" keyword in
"SBI account is blocked", so its own priority-ordering gap from phase 8 is
unchanged), but the new supervised classifier confidently recognizes
"bank_impersonation" and Phase 9's OTHER_SUSPICIOUS two-stage logic lets that
specific classification surface instead of being shadowed by the old
`UNKNOWN_SCAM` fallback. `isScam`, `scamType` (except bank_fraud, above), and
`riskScore` are otherwise untouched by phase 9 — none of those come from the
fusion arithmetic or the supervised classifier's own confidence except where
a pattern-layer scamType was already non-specific.
"""

import pytest

from packages.domain.risk import detector as scam_detector

pytestmark = pytest.mark.characterization

SCAM_BANK = {
    "lottery": "Congratulations! You won 25 lakh in KBC lottery. Pay processing fee to claim your prize now.",
    "bank_fraud": "Dear customer your SBI account is blocked. Complete KYC verification immediately or account will be closed.",
    "upi_fraud": "Send Rs 5000 to scammer@okaxis right now to release your refund",
    "job_scam": "Work from home data entry job. Salary 25000 per month. Pay registration fee of Rs 500 to start.",
    "phishing": "Your account is suspended. Click here to verify: http://sbi-verify-login.xyz/update",
    "investment_scam": "Guaranteed returns 1000% in crypto trading. Invest now, limited time offer. Double your money!",
    "romance_scam": "hello dear i am lonely and i love you, i miss you so much, can you send photo",
    "delivery_scam": "Your parcel is on hold at customs. Pay delivery charge of Rs 250 to release the consignment.",
    "otp_fraud": "URGENT: Share your OTP now to verify your account or it will be suspended immediately",
    "crypto_scam": "Bitcoin mining opportunity! Guaranteed returns with binance. Invest today and profit 1000%.",
}

BENIGN_BANK = {
    "greeting": "hey how are you doing today",
    "meeting": "Let us meet at the cafe around 6 in the evening",
    "family": "Mom asked me to buy vegetables on the way home",
    "work": "The deployment finished and the tests are green",
    "weather": "It is raining heavily here since morning",
}

# name -> (scamType, confidence, riskScore, sorted signalCategories)
#
# Word-boundary keyword matching (was plain substring -- "rs" inside
# "appears", "won" inside "known" -- see packages/domain/risk/keyword_match.py)
# changed several confidence/riskScore numbers below even where the label
# didn't change, because SUSPICIOUS_KEYWORDS/RISK_SIGNALS hit fewer bogus
# words. The behavioral-signal pass (packages/domain/risk/behavioral_signals.py)
# fixed the otp_fraud mislabel: "share your OTP" is now a recognized
# MFA_CODE_REQUEST/OTP_REQUEST behavioral signal, not just an isolated
# "verification" keyword bucket hit.
#
# One mislabel remains, deliberately not fixed in this pass -- a
# determine_scam_type() *priority-ordering* bug (generic keyword categories
# are checked before evidence the intelligence extractor already found), not
# the missing-evidence-category bug items 1-9 of the original audit asked for:
#   - upi_fraud -> delivery_scam: "release your refund" hits the generic
#     "delivery" keyword bucket, which is checked before `intelligence["upiIds"]`
#     even though a real UPI ID was already extracted.
#
# bank_fraud -> UNKNOWN_SCAM (the twin of the bug above -- "SBI"/"KYC" appear
# but the "authority" RISK_SIGNALS category never fires since the message
# says "SBI", not "bank") is fixed as of phase 9, NOT by touching
# determine_scam_type()'s priority order, but as a side effect of two
# independent phase 9 changes: (1) OTHER_SUSPICIOUS (item 7) means a
# non-specific pattern-layer guess no longer blocks a more specific answer
# from a different layer the way the old "other"/"UNKNOWN_SCAM" truthy-string
# check did, and (2) the retrained supervised classifier (1321 examples vs.
# the old 90) confidently recognizes "bank_impersonation" for this exact
# phrasing, clearing the new, higher 0.65 threshold. The underlying
# rules-layer priority bug is technically still there; it's just no longer
# the last word for this specific message.
#
# Confidence numbers changed again in Phase 10: packages/ml/text/semantic.py
# (sentence-transformers/all-MiniLM-L6-v2 + LogisticRegression) now runs
# unconditionally alongside the supervised TF-IDF classifier and contributes
# a third RiskSignal to fusion.fuse()'s renormalization -- see
# docs/ml/phase10-semantic-evaluation.md. scamType/riskScore/signalCategories
# are untouched (regenerated and diffed against the phase-9 values above to
# confirm); only the renormalized `confidence` float moved.
GOLDEN_SCAM = {
    "lottery": ("lottery", 0.436, 100, ["financial", "rewards", "urgency"]),
    "bank_fraud": ("bank_fraud", 0.663, 58, ["emotional", "pressure", "urgency", "verification"]),
    "upi_fraud": ("delivery_scam", 0.348, 60, ["delivery", "financial", "urgency"]),
    "job_scam": ("job_scam", 0.332, 100, ["financial", "job_scam"]),
    "phishing": ("phishing", 0.513, 40, ["platform", "verification"]),
    "investment_scam": ("crypto_scam", 0.866, 100, ["crypto", "emotional", "financial", "urgency"]),
    "romance_scam": ("romance_scam", 0.21, 66, ["emotional", "romance"]),
    "delivery_scam": ("delivery_scam", 0.611, 100, ["authority", "delivery", "financial"]),
    "otp_fraud": ("mfa_code_theft", 0.614, 90, ["urgency", "verification"]),
    "crypto_scam": ("crypto_scam", 0.782, 100, ["crypto", "emotional", "financial", "urgency"]),
}

GOLDEN_BENIGN = {
    "greeting": ("other", 0.032, 10, ["urgency"]),
    "meeting": ("romance_scam", 0.032, 10, ["romance"]),  # "meet" hits the romance list
    "family": ("other", 0.0, 0, []),
    "work": ("other", 0.0, 0, []),
    "weather": ("other", 0.0, 0, []),
}


@pytest.mark.parametrize("name", sorted(SCAM_BANK))
async def test_analyze_flags_known_scams(name):
    scam_type, confidence, risk_score, categories = GOLDEN_SCAM[name]
    result = await scam_detector.analyze(SCAM_BANK[name])

    assert result["isScam"] is True
    assert result["scamType"] == scam_type
    assert result["confidence"] == confidence
    assert result["riskScore"] == risk_score
    assert sorted(result["signalCategories"]) == categories


@pytest.mark.parametrize("name", sorted(BENIGN_BANK))
async def test_analyze_passes_benign_messages(name):
    scam_type, confidence, risk_score, categories = GOLDEN_BENIGN[name]
    result = await scam_detector.analyze(BENIGN_BANK[name])

    assert result["isScam"] is False
    assert result["scamType"] == scam_type
    assert result["confidence"] == confidence
    assert result["riskScore"] == risk_score
    assert sorted(result["signalCategories"]) == categories


async def test_analyze_response_shape():
    result = await scam_detector.analyze(SCAM_BANK["lottery"])
    assert set(result) == {
        "isScam", "confidence", "scamType", "indicators", "language",
        "ml_confidence", "riskScore", "signalCategories", "reasoning", "method",
        "signals",  # phase 8: the RiskSignals fusion actually ran over
        "evidence", "ml_prediction",  # item 11: per-detector evidence attribution
        "semantic_prediction",  # phase 10: MiniLM classifier's own class/confidence
    }
    assert result["method"] == "universal_detection"
    assert len(result["indicators"]) <= 15


async def test_analyze_degrades_without_ml_or_llm():
    """Lite mode + no keys: neutral ML values, English default, no crash."""
    result = await scam_detector.analyze(SCAM_BANK["lottery"])
    assert result["ml_confidence"] == 0.0
    assert result["language"] == "en"


def test_pattern_detection_threshold():
    """is_scam = riskScore >= 18 or >= 2 signal categories or confidence > 0.30."""
    assert scam_detector.pattern_based_detection(BENIGN_BANK["family"])["isScam"] is False
    assert scam_detector.pattern_based_detection(SCAM_BANK["phishing"])["isScam"] is True
    # Single "urgency" hit scores 10 and one category: below both thresholds.
    single = scam_detector.pattern_based_detection(BENIGN_BANK["greeting"])
    assert single["riskScore"] == 10
    assert single["isScam"] is False


def test_risk_score_caps_at_100():
    assert scam_detector.calculate_risk_score(SCAM_BANK["lottery"] * 5)["score"] == 100


def test_determine_scam_type_priority():
    """Specific signals beat intelligence, which beats generic keyword rules."""
    assert scam_detector.determine_scam_type({"job_scam": {}, "rewards": {}}, {}) == "job_scam"
    assert scam_detector.determine_scam_type({"rewards": {}}, {"phishingLinks": ["x"]}) == "phishing"
    assert scam_detector.determine_scam_type({}, {"upiIds": ["a@ybl"]}) == "upi_fraud"
    assert scam_detector.determine_scam_type({"rewards": {}}, {}) == "lottery"
    assert scam_detector.determine_scam_type({"a": {}, "b": {}, "c": {}}, {}) == "UNKNOWN_SCAM"
    assert scam_detector.determine_scam_type({}, {}) == "other"


def test_determine_scam_type_requires_supporting_evidence():
    """Item 6's fix: bank_fraud/investment_scam are conclusions that need
    their own evidence, not just co-occurrence of two unrelated generic
    keyword buckets ("verification" also fires on "confirm"/"kyc"; "authority"
    also fires on "hr"/"manager"/"delivery" -- neither means banking)."""
    signals = {"verification": {}, "authority": {}}
    assert scam_detector.determine_scam_type(signals, {}, "") == "other"
    assert scam_detector.determine_scam_type(signals, {}, "Your SBI bank account needs KYC.") == "bank_fraud"

    signals = {"financial": {}, "urgency": {}}
    assert scam_detector.determine_scam_type(signals, {}, "") == "other"
    assert (
        scam_detector.determine_scam_type(signals, {}, "Guaranteed returns, invest today.")
        == "investment_scam"
    )
