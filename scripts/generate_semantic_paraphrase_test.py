"""Phase 10 item 10: a larger semantic paraphrase test than the 12-pair
ml-models/evaluation/paraphrase_pairs.json probe.

    uv run python scripts/generate_semantic_paraphrase_test.py

Writes ml-models/evaluation/semantic_paraphrase_test.json (120+ examples,
three categories):
  - mfa_verification_intent: requests for an MFA/OTP/authenticator value,
    phrased both in the vocabulary behavioral_signals.py already anchors on
    ("verification code") and paraphrased away from it ("the six digits
    displayed on your phone").
  - credential_intent: requests for a password/login secret, same known-vs-
    paraphrased mix.
  - benign_security_context: sentences that mention the same vocabulary
    (OTP, password, MFA, authentication) while explicitly NOT requesting the
    secret -- warnings, policy statements, confirmations. The model must
    tell "requesting a secret" apart from "discussing why secrets must not
    be shared" (spec item 10's stated purpose), not just react to shared
    vocabulary.

Not used for training or threshold selection -- read-only evaluation input
for scripts/eval_unseen.py-style candidates, same as paraphrase_pairs.json.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUT_PATH = ROOT / "ml-models" / "evaluation" / "semantic_paraphrase_test.json"

# ---------------------------------------------------------------------------
# MFA / verification intent -- what's being asked for, known phrasing mixed
# with paraphrases that avoid the literal trigger words.
# ---------------------------------------------------------------------------
MFA_SECRETS = [
    "the verification code",  # known
    "the OTP",  # known
    "the MFA code",  # known
    "the one-time password",  # known
    "the six digits displayed on your phone",  # paraphrase
    "the number that appeared after the authentication challenge",  # paraphrase
    "the temporary value shown by the authenticator",  # paraphrase
    "the number generated during sign-in",  # paraphrase
    "the code your banking app just displayed",  # paraphrase
    "the digits currently on your screen",  # paraphrase
    "the value the app generated a moment ago",  # paraphrase
    "the number your device is showing right now",  # paraphrase
    "the one-time value from your authenticator app",  # paraphrase
    "whatever number just popped up after you logged in",  # paraphrase
    "the passcode your phone just buzzed with",  # paraphrase
    "the short code that flashed on your lock screen",  # paraphrase
    "the sign-in number your authenticator just refreshed",  # paraphrase
    "the digits your bank just texted over",  # paraphrase
]

CREDENTIAL_SECRETS = [
    "your password",  # known
    "what you enter to sign in",  # paraphrase
    "the secret used to authenticate",  # paraphrase
    "the credential associated with the account",  # paraphrase
    "the value you normally use to access the workstation",  # paraphrase
    "your login details",  # known-ish
    "the passphrase you use every day",  # paraphrase
    "whatever you type into the sign-in box",  # paraphrase
    "the string you use to unlock your account",  # paraphrase
    "your account secret",  # paraphrase
    "the thing you type in right before you get into your inbox",  # paraphrase
    "the word or phrase that unlocks your account",  # paraphrase
    "whatever you use to prove it's really you logging in",  # paraphrase
    "the private phrase tied to your profile",  # paraphrase
    "the entry code your account was set up with",  # paraphrase
]

REQUEST_FRAMES = [
    "Send me {x}.",
    "Read {x} out loud.",
    "What is {x}?",
    "Tell me {x} so I can verify your identity.",
    "Please share {x} with me now.",
    "Can you type {x} here?",
    "I need {x} to complete the process.",
    "Forward {x} to this number.",
    "Reply with {x} right away.",
    "Give me {x}, quickly.",
]

BENIGN_SECURITY_CONTEXT = [
    "Never share your verification code with support.",
    "Security policy prohibits sharing authentication values.",
    "Confirm whether the MFA prompt appeared, but do not provide the code.",
    "The security team will never ask for your password.",
    "Please don't tell anyone your OTP, even if they claim to be from the bank.",
    "We will never call and ask for your six-digit code.",
    "IT will never request your login credentials over phone or email.",
    "Do not share the number displayed on your authenticator app with anyone.",
    "Reminder: support staff cannot see or ask for your password.",
    "If someone asks for your verification code, it's a scam -- hang up.",
    "Your MFA enrollment is complete; no action needed on your part.",
    "Please confirm that the authentication prompt appeared on your device.",
    "Two-factor authentication is now mandatory for all employees.",
    "I reset my own password this morning without any issue.",
    "Nice work on the demo, the stakeholders seemed impressed.",
    "Our helpdesk will never ask you to read out your one-time code.",
    "Just a heads-up: authenticator codes should never be shared, even with IT.",
    "You do not need to give anyone your password to reset it yourself.",
    "The bank confirmed they never request OTPs by phone.",
    "Training reminder: report anyone who asks for your credentials.",
]

BENIGN_OTHER = [
    "Standup got pushed to 4pm, same room as always.",
    "Can you send over the slide deck before tomorrow's call?",
    "Lunch is in the break room if anyone's hungry.",
    "The quarterly report is due next Friday.",
    "Thanks for covering my shift yesterday.",
    "Let's sync up about the roadmap sometime this week.",
    "The printer on the third floor is out of toner again.",
    "Happy birthday! Hope you have a great day.",
    "The new office chairs arrived this morning.",
    "Traffic was terrible on the way in today.",
    "Can we push the standup to 9:30 instead of 9?",
    "Feedback on the mockups from the client was positive overall.",
    "Reminder to submit your timesheet by end of day.",
    "The coffee machine is finally fixed.",
    "Great weather for the team outing this weekend.",
]


def _build_examples() -> list[dict]:
    examples: list[dict] = []

    for i, secret in enumerate(MFA_SECRETS):
        frame = REQUEST_FRAMES[i % len(REQUEST_FRAMES)]
        examples.append({
            "text": frame.format(x=secret),
            "is_scam": True,
            "category": "mfa_verification_intent",
            "known_phrasing": secret in ("the verification code", "the OTP", "the MFA code", "the one-time password"),
        })
        # second and third frame per secret for volume/diversity
        for offset in (3, 6):
            frame_n = REQUEST_FRAMES[(i + offset) % len(REQUEST_FRAMES)]
            examples.append({
                "text": frame_n.format(x=secret),
                "is_scam": True,
                "category": "mfa_verification_intent",
                "known_phrasing": secret in ("the verification code", "the OTP", "the MFA code", "the one-time password"),
            })

    for i, secret in enumerate(CREDENTIAL_SECRETS):
        frame = REQUEST_FRAMES[(i + 1) % len(REQUEST_FRAMES)]
        examples.append({
            "text": frame.format(x=secret),
            "is_scam": True,
            "category": "credential_intent",
            "known_phrasing": secret in ("your password", "your login details"),
        })
        for offset in (5, 8):
            frame_n = REQUEST_FRAMES[(i + offset) % len(REQUEST_FRAMES)]
            examples.append({
                "text": frame_n.format(x=secret),
                "is_scam": True,
                "category": "credential_intent",
                "known_phrasing": secret in ("your password", "your login details"),
            })

    for text in BENIGN_SECURITY_CONTEXT:
        examples.append({"text": text, "is_scam": False, "category": "benign_security_context"})

    for text in BENIGN_OTHER:
        examples.append({"text": text, "is_scam": False, "category": "benign_other"})

    # de-dupe while preserving order (a few request-frame/secret combos can
    # coincide across the two frame picks above)
    seen = set()
    deduped = []
    for ex in examples:
        if ex["text"] in seen:
            continue
        seen.add(ex["text"])
        deduped.append(ex)
    return deduped


def main() -> None:
    examples = _build_examples()
    data = {
        "_comment": (
            "Phase 10 item 10: larger semantic paraphrase test (>=100 examples). "
            "mfa_verification_intent/credential_intent mix known phrasing (canonical "
            "trigger words) with paraphrases that avoid them entirely. "
            "benign_security_context mentions the same vocabulary while explicitly "
            "NOT requesting the secret (warnings/policy/confirmations) -- the "
            "distinguishing test this file targets: requesting a secret vs. "
            "discussing why secrets must not be shared. benign_other is unrelated "
            "everyday text, for baseline FPR breadth. Not used for training or "
            "threshold selection."
        ),
        "purpose": "semantic_paraphrase_test",
        "categories": ["mfa_verification_intent", "credential_intent", "benign_security_context", "benign_other"],
        "examples": examples,
    }
    OUT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    from collections import Counter

    print(f"Wrote {len(examples)} examples to {OUT_PATH.relative_to(ROOT)}")
    print("category counts:", Counter(ex["category"] for ex in examples))
    print("is_scam counts:", Counter(ex["is_scam"] for ex in examples))


if __name__ == "__main__":
    main()
