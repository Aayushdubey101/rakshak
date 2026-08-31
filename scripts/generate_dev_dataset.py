"""Phase 9: generate a larger, structurally varied development corpus.

    uv run python scripts/generate_dev_dataset.py

Writes ml-models/evaluation/dev_train_set_v2.json (training) and
ml-models/evaluation/threshold_validation_set.json (held out from training --
used only for model/threshold selection in scripts/train_and_compare_models.py).
Both are disjoint from ml-models/evaluation/unseen_validation_set.json and
labeled_set.json (verified by scripts/check_dataset_overlap.py).

Approach: combinatorial templates, not word-substitution clones. Each
malicious category composes independent slots (sender/pretext identity,
request verb, secret-noun phrasing, register, urgency, URL presence). Half of
each category's secret-noun phrasings deliberately avoid every term
packages/domain/risk/behavioral_signals.py's regexes anchor on (no "otp",
"password", "verification code", "mfa code", "authentication token", "api
key", "session token", "card number/cvv", "payment/transfer") so the
generalization gap this phase targets is actually represented in training/
validation data, not just in the frozen unseen set.
"""

from __future__ import annotations

import itertools
import json
import random
from pathlib import Path

ROOT = Path(__file__).parent.parent
OUT_DIR = ROOT / "ml-models" / "evaluation"

RNG_SEED = 20260810
VAL_FRACTION = 0.22


# ---------------------------------------------------------------------------
# Shared slot pools
# ---------------------------------------------------------------------------

FORMAL_SENDERS = [
    "This is IT Support.", "Security Operations Center here.",
    "This is the Systems Administration team.", "Compliance Office here.",
    "This is your Account Services representative.",
    "Endpoint Operations here.", "This is the Identity & Access team.",
    "Network Operations Center here.", "This is the Helpdesk.",
    "Corporate Security here.",
]
CASUAL_SENDERS = [
    "Hey, it's Sam from IT,", "Hi, it's Priya from the helpdesk,",
    "Yo, this is Dave from tech,", "Hi there, it's the support guy again,",
    "hey it's Alex from security,", "quick note from Jordan on the ops team,",
    "hi, Raj here from account services,", "hey, it's Mia covering IT today,",
]

FORMAL_PRETEXTS = [
    "we detected unusual sign-in activity on your account",
    "your session is flagged for the pre-maintenance review",
    "the access reconciliation for your account is still pending",
    "there is a billing discrepancy on file that needs resolution",
    "your workstation session appears to be orphaned after last night's update",
    "the quarterly audit comparison flagged your profile for follow-up",
    "we are finalizing the endpoint migration for your device",
    "your account was included in this week's compliance check",
    "a routine security review is in progress for your profile",
    "the directory sync reported a mismatch on your credentials record",
]
CASUAL_PRETEXTS = [
    "your account looks a bit weird on our end today",
    "something's off with your last login, nothing major",
    "we're just tidying up some old sessions before the weekend",
    "your profile got caught in a batch we're cleaning up",
    "there's a small hiccup with your account we're sorting out",
    "we noticed your device flagged during the routine sweep",
]

REQUEST_VERBS_FORMAL = [
    "Please reply with", "Kindly share", "Please provide",
    "We would ask that you send", "Please forward", "Please confirm by sending",
]
REQUEST_VERBS_CASUAL = [
    "Can you just send me", "Mind sharing", "Could you paste",
    "Just reply with", "Go ahead and send over", "Can you read out",
]

URGENCY_SUFFIXES = [
    " before the window closes today.", " as soon as possible.",
    " within the next few minutes.", " right away, thanks.",
    "",  # no urgency
    "",
]
URL_SUFFIXES = [
    "", "", "",  # majority no URL, since this signal is about secret-request wording
    " You can also confirm at http://account-check-portal.example/verify.",
    " Reference link: http://secure-verify-status.example/session.",
]


def _compose(sender: str, pretext: str, verb: str, secret: str, urgency: str, url: str) -> str:
    return f"{sender} {pretext}. {verb} {secret}{urgency}{url}"


def _grid(senders, pretexts, verbs, secrets, n_target: int, seed_offset: int) -> list[str]:
    combos = list(itertools.product(senders, pretexts, verbs, secrets, URGENCY_SUFFIXES, URL_SUFFIXES))
    rng = random.Random(RNG_SEED + seed_offset)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[str] = []
    for sender, pretext, verb, secret, urgency, url in combos:
        text = _compose(sender, pretext, verb, secret, urgency, url)
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------
# MFA / OTP theft (target combined ~200)
# ---------------------------------------------------------------------------

MFA_SECRETS_REGEX_VISIBLE = [
    "the verification code we just sent", "your one-time password", "the OTP on your phone",
    "the MFA code shown on your device", "the authenticator code currently displayed",
    "the one-time code from your app",
]
MFA_SECRETS_PARAPHRASE = [
    "the six digits on your screen right now", "the number that just popped up on your phone",
    "whatever value appears after you tap sign in", "the short code your app just showed you",
    "the digits your device is currently displaying", "the number that flashed on your lock screen",
    "the temporary number shown when you signed in", "what your authenticator app is showing right now",
]


def gen_mfa(n_target: int) -> list[dict]:
    secrets = MFA_SECRETS_REGEX_VISIBLE + MFA_SECRETS_PARAPHRASE
    texts = _grid(
        FORMAL_SENDERS + CASUAL_SENDERS, FORMAL_PRETEXTS + CASUAL_PRETEXTS,
        REQUEST_VERBS_FORMAL + REQUEST_VERBS_CASUAL, secrets, n_target, seed_offset=1,
    )
    return [{"text": t, "label": "mfa_code_theft"} for t in texts]


# ---------------------------------------------------------------------------
# Credential access (target combined ~200)
# ---------------------------------------------------------------------------

CRED_SECRETS_REGEX_VISIBLE = [
    "your account password", "your API key", "your session token",
    "the secret key for the integration", "your login password",
]
CRED_SECRETS_PARAPHRASE = [
    "what you type into the sign-in box", "the string you use to unlock your account",
    "the phrase you enter every morning to log in", "the credential you use for the VPN client",
    "the value stored in your password manager for this account",
    "the access string tied to your workstation profile",
    "whatever you type in right before you get into your inbox",
]


def gen_credential(n_target: int) -> list[dict]:
    secrets = CRED_SECRETS_REGEX_VISIBLE + CRED_SECRETS_PARAPHRASE
    texts = _grid(
        FORMAL_SENDERS + CASUAL_SENDERS, FORMAL_PRETEXTS + CASUAL_PRETEXTS,
        REQUEST_VERBS_FORMAL + REQUEST_VERBS_CASUAL, secrets, n_target, seed_offset=2,
    )
    return [{"text": t, "label": "credential_access"} for t in texts]


# ---------------------------------------------------------------------------
# Social engineering (target combined ~200) -- pretext/authority pressure,
# no explicit secret request; the ask is to bypass a control.
# ---------------------------------------------------------------------------

SE_IDENTITIES = [
    "Hey, it's Mark from finance,", "This is the CEO,", "It's Priya from legal,",
    "Hi, this is your regional director,", "This is Alex, covering for the CFO,",
    "It's Sam, I handle vendor approvals,", "Hey it's Dana from procurement,",
    "This is Jordan from the executive office,",
]
SE_ASKS = [
    "can you approve this directly and skip the usual sign-off",
    "please don't loop in compliance on this one, just push it through",
    "keep this between us for now, I'll explain everything later",
    "can you process it quietly before anyone else notices",
    "let's not verify this through the normal channel, just proceed",
    "bypass the two-person check just this once, I'll take responsibility",
    "don't mention this to your manager yet, just help me get it done",
    "handle this off the record before the board meeting",
    "trust me on this, skip the approval step and get it done today",
    "delete this message after reading and just do what I've asked",
]
SE_URGENCY = ["", "", " I need this before end of day.", " Timing really matters here.", " This can't wait until tomorrow."]


def gen_social_engineering(n_target: int) -> list[dict]:
    combos = list(itertools.product(SE_IDENTITIES, SE_ASKS, SE_URGENCY))
    rng = random.Random(RNG_SEED + 3)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[dict] = []
    for identity, ask, urgency in combos:
        text = f"{identity} I'm tied up right now, {ask}.{urgency}"
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "label": "social_engineering"})
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------
# IT support pretext (target combined ~150) -- impersonation opener, request
# to confirm/read out credentials tied explicitly to an IT/helpdesk cover story.
# ---------------------------------------------------------------------------

IT_OPENERS = [
    "This is IT support.", "Helpdesk calling about your open ticket.",
    "This is desktop support.", "Systems team here, rolling out tonight's update.",
    "Tech support, your machine was flagged for a scan.",
    "This is the network operations team.", "IT compliance calling ahead of the audit.",
    "This is remote support, following up on your call.",
]
IT_ASKS_VISIBLE = [
    "please confirm your username and password to close out the ticket",
    "we need to verify your login before restoring access",
    "please confirm your VPN credentials so we can troubleshoot",
    "read out anything that appears on your screen during the fix",
    "please confirm your sign-in so we don't lock the account",
]
IT_ASKS_PARAPHRASE = [
    "just tell me what shows up on your screen once I start the remote session",
    "walk me through what you see after you type in your usual details",
    "let me know the value your machine displays once you're logged in",
    "read me back whatever appears once you attempt to sign in",
]


def gen_it_support(n_target: int) -> list[dict]:
    asks = IT_ASKS_VISIBLE + IT_ASKS_PARAPHRASE
    combos = list(itertools.product(IT_OPENERS, asks, URGENCY_SUFFIXES))
    rng = random.Random(RNG_SEED + 4)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[dict] = []
    for opener, ask, urgency in combos:
        text = f"{opener} We need you to {ask}{urgency}"
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "label": "it_support_pretext"})
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------
# Bank impersonation (target combined ~150)
# ---------------------------------------------------------------------------

BANK_OPENERS = [
    "Dear customer, your SBI account is blocked.", "This is your bank calling about suspicious activity.",
    "Bank security alert: a large transfer was attempted.", "Your net banking access will be suspended.",
    "This is the fraud department at your bank.", "Your card has been blocked for security reasons.",
    "HDFC alert: your KYC update is overdue.", "ICICI security team here, unusual login detected.",
]
BANK_ASKS = [
    "share your CVV to cancel the transaction immediately",
    "confirm your debit card number to secure your account",
    "verify your account number and PIN today",
    "share your net banking password to stop the transaction",
    "confirm your account number and date of birth to avoid closure",
    "verify your PIN to secure the account right away",
    "complete KYC verification immediately or the account will be closed",
    "reply with your card details to reverse the hold",
]


def gen_bank(n_target: int) -> list[dict]:
    combos = list(itertools.product(BANK_OPENERS, BANK_ASKS, URGENCY_SUFFIXES))
    rng = random.Random(RNG_SEED + 5)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[dict] = []
    for opener, ask, urgency in combos:
        text = f"{opener} Please {ask}{urgency}"
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "label": "bank_impersonation"})
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------
# Investment fraud (target combined ~150)
# ---------------------------------------------------------------------------

INVEST_HOOKS = [
    "Guaranteed returns of {pct}% in crypto trading.", "Our trading desk guarantees {pct}% monthly returns with zero risk.",
    "This exclusive fund never loses, early investors already see {pct}% gains.",
    "Join our VIP investment group, members double their capital in weeks.",
    "Limited-time forex opportunity, guaranteed daily profits.",
    "Our stock tips have a {pct}% success rate this year.",
    "This trading bot guarantees consistent profit with no downside.",
    "Bitcoin mining opportunity, guaranteed returns with binance.",
]
INVEST_CTAS = [
    "Invest now, limited time offer.", "Deposit today to lock in this rate.",
    "Minimum deposit required today.", "Act now before the offer closes.",
    "Double your money in weeks.", "Sign up before slots run out.",
]


def gen_investment(n_target: int) -> list[dict]:
    pcts = ["100", "300", "500", "1000", "20"]
    combos = list(itertools.product(INVEST_HOOKS, INVEST_CTAS, pcts))
    rng = random.Random(RNG_SEED + 6)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[dict] = []
    for hook, cta, pct in combos:
        text = f"{hook.format(pct=pct)} {cta}"
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "label": "investment_fraud"})
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------
# Payment fraud (target combined ~150) -- account/invoice redirection, no
# credential ask, no URL required.
# ---------------------------------------------------------------------------

PAYMENT_OPENERS = [
    "Our bank details have changed.", "The vendor's payout account changed recently.",
    "The supplier switched accounts this month.", "There's an update to the invoice payment details.",
    "The client's payment account was corrected.", "Finance updated the wire instructions for this vendor.",
]
PAYMENT_ASKS = [
    "please send the payment to the new account immediately",
    "please redirect this month's transfer to the corrected account number attached",
    "please process the outstanding invoice using the new banking details before the deadline",
    "please confirm and wire the funds to the new details today",
    "please expedite the wire transfer to the new account, they're waiting on it",
    "please update the vendor payment account before processing this month's invoice",
]


def gen_payment(n_target: int) -> list[dict]:
    combos = list(itertools.product(PAYMENT_OPENERS, PAYMENT_ASKS, URGENCY_SUFFIXES))
    rng = random.Random(RNG_SEED + 7)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[dict] = []
    for opener, ask, urgency in combos:
        text = f"{opener} {ask.capitalize()}{urgency}"
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "label": "payment_fraud"})
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------
# Phishing (target combined ~200) -- URL is the defining evidence.
# ---------------------------------------------------------------------------

PHISH_OPENERS = [
    "Your account is suspended.", "Unusual activity was detected on your account.",
    "Your payment could not be processed.", "Your document is ready for e-signature.",
    "Your parcel is on hold at customs.", "Your subscription has expired.",
    "Your password will expire in 24 hours.", "A new device signed into your account.",
]
PHISH_DOMAINS = [
    "hdfc-secure-relogin.xyz/update", "profile-reverify-portal.top/login",
    "alert-status-check.click/review", "invoice-payment-fix.xyz/pay",
    "esign-doc-pending.info/sign", "parcel-fee-release.buzz/pay",
    "reset-access-now.ga/reset", "device-alert-confirm.tk/confirm",
]
PHISH_CTAS = [
    "Click here to verify:", "Review your account now at",
    "Update your billing information here:", "Sign here before it expires:",
    "Pay the release fee here:", "Reset your password here:",
]


def gen_phishing(n_target: int) -> list[dict]:
    combos = list(itertools.product(PHISH_OPENERS, PHISH_CTAS, PHISH_DOMAINS))
    rng = random.Random(RNG_SEED + 8)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[dict] = []
    for opener, cta, domain in combos:
        text = f"{opener} {cta} http://{domain}"
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "label": "phishing"})
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------
# Benign (target combined ~300) -- plain everyday messages, legitimate
# security/IT notices using the same vocabulary scammers use, and hard
# negatives that explicitly mention the secret noun in a non-request context.
# ---------------------------------------------------------------------------

BENIGN_PLAIN = [
    "what time works for you for lunch tomorrow", "Grabbing groceries on the way back, need anything?",
    "The build pipeline is green again after this morning's fix.",
    "It has been sunny all week, finally some good weather.",
    "The router in the break room got swapped out yesterday, ask facilities if it's still flaky.",
    "The new hire orientation is scheduled for Wednesday at 9am.",
    "Sprint review got pushed to Thursday afternoon instead.",
    "Left the notes from today's call in the shared drive, take a look whenever.",
    "The vendor confirmed the shipment already went out this morning.",
    "The elevator on the east side is out for repairs until Friday.",
    "Nice work wrapping up the migration ahead of schedule.",
    "The cafeteria is trying a new menu starting next week.",
    "Remember to log your hours before the weekly cutoff.",
    "The team lunch got moved to the rooftop this time.",
    "Told mom we'd be there by seven, traffic permitting.",
    "The last invoice already went through, nothing else pending on it.",
    "Appreciate you covering the call while I was out.",
    "The parking garage entrance is closed for repaving this weekend.",
    "Your cab is a few minutes out, driver's name is Karan.",
    "The gym added a new set of weights near the entrance.",
    "Catching the early train, should be in by nine.",
    "Reading group is back on for the 20th this time.",
    "Construction on the main road means the detour is faster right now.",
]

BENIGN_SECURITY_VOCAB = [
    "The certificate on the internal dashboard renews automatically next week; nothing for us to do.",
    "Overnight maintenance runs from 1am to 3am Sunday, expect brief tool outages.",
    "You can enroll in two-factor from the account settings page whenever you're ready.",
    "This quarter's access review wrapped up with no findings for our group.",
    "Your login was paused briefly after repeated attempts and cleared itself automatically.",
    "Minimum password length is going up to 14 characters starting next release.",
    "Changed my own login credentials this morning, all working as expected now.",
    "There's a short refresher on phishing awareness scheduled for next week.",
    "Admin accounts will require two-step sign-in starting next quarter.",
    "The automatic sign-out after inactivity is intentional, not a bug.",
    "Saw the note about the latest phishing campaign making the rounds, worth a skim.",
    "Setup instructions for the authenticator app are posted on the internal wiki.",
    "This cycle's compliance review found no gaps in our access setup.",
    "Billing renews automatically at the same rate as last cycle, no changes needed.",
    "A locked-looking account after 15 idle minutes is just the normal timeout kicking in.",
    "Updated firewall rules deploy tonight automatically, no action needed from users.",
    "Session refresh happens in the background now, so you shouldn't get logged out mid-task.",
    "Service credentials rotate on their own schedule each quarter, nothing manual required.",
]

BENIGN_HARD_NEGATIVES = [
    "Nobody from our helpdesk will ever ask you to read out a one-time code, don't give it out if asked.",
    "The sign-in method upgrade rolls out automatically overnight, you won't need to do anything.",
    "Did the two-step prompt show up on your end? No need to tell me the number itself.",
    "Heads up that your login expires this week, change it only through the official app.",
    "Compliance is spot-checking sign-in records this week; nobody needs to hand over their login for that.",
    "Nobody on this team will text asking for the digits shown on your screen, ignore it if it happens.",
    "Rotation of service credentials happens on our side automatically, you won't need to send anything.",
    "If someone calls claiming to be support and asks you to read back a code, that's not really us.",
    "Support will never ask you to say your login out loud over a call, hang up if that happens.",
    "Just a note that our fraud team never calls asking customers to confirm a PIN over the phone.",
    "Our staff are trained to never request a one-time code from anyone by phone or chat.",
    "Confirmed the reset went through fine on my end, nothing further needed from you.",
    "Don't hand your card details to anyone who calls claiming to be from the bank.",
    "Keep your sign-in string to yourself, even if someone claims to be from our team.",
    "The bank will never ask you to read out the number on the back of your card.",
    "Whatever you type into the login screen stays with you, we never ask for it directly.",
    "If IT ever asks you to say a password out loud, treat that as suspicious, not routine.",
    "This week's audit only pulled logs, no one on that team asked for anyone's credentials.",
    "We already rotated that key internally, no need to forward your old one to anyone.",
    "The automatic top-up on your subscription is expected, nothing you need to approve.",
]


def gen_benign(n_target: int) -> list[dict]:
    pool = BENIGN_PLAIN + BENIGN_SECURITY_VOCAB + BENIGN_HARD_NEGATIVES
    # Combine base pool with light variation (time-of-day / greeting prefixes)
    # so we exceed the pool size without turning into a scam-shaped template.
    prefixes = ["", "Quick note: ", "FYI - ", "Reminder: ", "Update: ", "Hey, "]
    combos = list(itertools.product(prefixes, pool))
    rng = random.Random(RNG_SEED + 9)
    rng.shuffle(combos)
    seen: set[str] = set()
    out: list[dict] = []
    for prefix, base in combos:
        text = f"{prefix}{base}"
        if text in seen:
            continue
        seen.add(text)
        out.append({"text": text, "label": "benign"})
        if len(out) >= n_target:
            break
    return out


# ---------------------------------------------------------------------------

TARGETS = {
    "benign": 300,
    "mfa_code_theft": 200,
    "credential_access": 200,
    "social_engineering": 200,
    "it_support_pretext": 150,
    "bank_impersonation": 150,
    "investment_fraud": 150,
    "payment_fraud": 150,
    "phishing": 200,
}

GENERATORS = {
    "benign": gen_benign,
    "mfa_code_theft": gen_mfa,
    "credential_access": gen_credential,
    "social_engineering": gen_social_engineering,
    "it_support_pretext": gen_it_support,
    "bank_impersonation": gen_bank,
    "investment_fraud": gen_investment,
    "payment_fraud": gen_payment,
    "phishing": gen_phishing,
}


def main() -> None:
    all_examples: dict[str, list[dict]] = {}
    for label, target in TARGETS.items():
        examples = GENERATORS[label](target)
        all_examples[label] = examples

    train, val = [], []
    rng = random.Random(RNG_SEED)
    achieved_counts = {}
    for label, examples in all_examples.items():
        rng.shuffle(examples)
        n_val = max(1, round(len(examples) * VAL_FRACTION))
        val.extend(examples[:n_val])
        train.extend(examples[n_val:])
        achieved_counts[label] = {"total": len(examples), "train": len(examples) - n_val, "val": n_val}

    rng.shuffle(train)
    rng.shuffle(val)

    train_doc = {
        "_comment": (
            "Phase 9 development/training data (v2) -- combinatorial templates, "
            "not word-substitution clones. Roughly half of MFA/credential "
            "secret-noun phrasings deliberately avoid every term "
            "behavioral_signals.py's regexes anchor on. Never evaluated for "
            "reported metrics -- see threshold_validation_set.json and "
            "unseen_validation_set.json for that."
        ),
        "purpose": "supervised_classifier_training_v2",
        "labels": sorted(TARGETS),
        "examples": train,
    }
    val_doc = {
        "_comment": (
            "Phase 9 held-out validation split -- generated from the SAME "
            "templates as dev_train_set_v2.json but a disjoint sample, so it is "
            "not independent of the training distribution the way "
            "unseen_validation_set.json is. Used ONLY for model comparison and "
            "threshold selection (scripts/train_and_compare_models.py). Never "
            "used to report final generalization numbers -- that is "
            "unseen_validation_set.json's job, touched exactly once, at the end."
        ),
        "purpose": "threshold_and_model_selection",
        "labels": sorted(TARGETS),
        "examples": [{**e, "is_scam": e["label"] != "benign", "category": e["label"]} for e in val],
    }

    (OUT_DIR / "dev_train_set_v2.json").write_text(json.dumps(train_doc, indent=2), encoding="utf-8")
    (OUT_DIR / "threshold_validation_set.json").write_text(json.dumps(val_doc, indent=2), encoding="utf-8")

    print(f"train: {len(train)} examples, val: {len(val)} examples")
    for label, counts in sorted(achieved_counts.items()):
        target = TARGETS[label]
        flag = "OK" if counts["total"] >= target else f"SHORT (target {target})"
        print(f"  {label}: total={counts['total']} train={counts['train']} val={counts['val']}  {flag}")


if __name__ == "__main__":
    main()
