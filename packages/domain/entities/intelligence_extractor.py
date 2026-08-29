import re
import logging
from collections import defaultdict

logger = logging.getLogger("uvicorn")

# 🔹 NEW: Transformer NER
from packages.ml.inference.hf import extract_entities
from packages.domain.risk.keyword_match import contains_word


PATTERNS = {
    "UPI": r"[a-zA-Z0-9._-]+@[a-zA-Z]{2,}",
    "PHONE": r"(?:\+91|91|0)?[6-9]\d{9}",
    "BANK_ACCOUNT": r"\b\d{9,18}\b",
    "URL": r"https?://[^\s<>\"{}|\\^`\[\]]+",
    "SUSPICIOUS_URL": r"(?:bit\.ly|tinyurl|goo\.gl|t\.co|is\.gd|v\.gd|short\.link|rebrand\.ly)/[a-zA-Z0-9]+"
}

SUSPICIOUS_KEYWORDS = {
    "urgency": ['urgent', 'immediately', 'now', 'hurry', 'limited time', 'expires', 'act now', 'quick'],
    "money": ['pay', 'payment', 'transfer', 'send money', 'rupees', 'rs', '₹', 'cash', 'amount'],
    "prizes": ['won', 'winner', 'lottery', 'prize', 'reward', 'cashback', 'bonus', 'lucky', 'jackpot'],
    "security": ['otp', 'pin', 'password', 'verify', 'blocked', 'suspended', 'kyc', 'update', 'security'],
    "offers": ['free', 'discount', 'offer', 'deal', 'scheme', 'investment', 'returns', 'profit', 'guaranteed'],
    "banking": ['account', 'bank', 'credit', 'debit', 'card', 'upi', 'paytm', 'phonepe', 'gpay']
}

# =========================
# EXISTING REGEX FUNCTIONS
# =========================

def extract_upi_ids(text: str) -> list[str]:
    matches = re.findall(PATTERNS["UPI"], text)
    email_domains = ['gmail', 'yahoo', 'hotmail', 'outlook', 'email', 'mail']
    
    # Known UPI providers for stricter validation
    upi_providers = ['paytm', 'ybl', 'okaxis', 'okhdfcbank', 'okicici', 'oksbi', 'ibl', 'axl', 'airtel', 'fbl', 'pockets']

    valid_upis = []
    for match in matches:
        domain = match.split('@')[1].lower()
        # Exclude email domains
        if any(ed in domain for ed in email_domains):
            continue
        # Prefer known UPI providers for higher confidence
        if any(provider in domain for provider in upi_providers):
            valid_upis.append(match.lower())  # Normalize to lowercase
        elif not any(ed in domain for ed in email_domains):
            # Still accept unknown domains if they're not email
            valid_upis.append(match.lower())
    
    return list(set(valid_upis))  # Deduplicate


def extract_phone_numbers(text: str) -> list[str]:
    matches = re.findall(PATTERNS["PHONE"], text)
    cleaned = []
    for phone in matches:
        # Normalize: remove country code and separators
        clean = re.sub(r"^(\+91|91|0)", "", phone)
        clean = re.sub(r"[\s\-()]", "", clean)  # Remove spaces, dashes, parentheses
        
        # Validate: must be 10 digits starting with 6-9
        if len(clean) == 10 and clean[0] in '6789':
            cleaned.append(clean)
    
    return list(set(cleaned))  # Deduplicate


def extract_bank_accounts(text: str) -> list[str]:
    matches = re.findall(PATTERNS["BANK_ACCOUNT"], text)
    valid_accounts = []
    for acc in matches:
        # Skip phone numbers (10 digits starting with 6-9)
        if len(acc) == 10 and re.match(r"^[6-9]", acc):
            continue
        # Skip dates (DDMMYYYY format)
        if len(acc) == 8 and re.match(r"^[0-3]\d[0-1]\d\d{4}$", acc):
            continue
        # Skip amounts/short numbers (too short to be bank account)
        if len(acc) < 9:
            continue
        # Valid bank account: 9-18 digits
        if 9 <= len(acc) <= 18:
            valid_accounts.append(acc)
    
    return list(set(valid_accounts))  # Deduplicate


def extract_phishing_links(text: str) -> list[str]:
    all_urls = re.findall(PATTERNS["URL"], text, re.IGNORECASE)
    suspicious_shorts = re.findall(PATTERNS["SUSPICIOUS_URL"], text, re.IGNORECASE)

    suspicious_set = set(suspicious_shorts)

    for url in all_urls:
        is_suspicious = (
            re.search(r"https?://\d+\.\d+\.\d+\.\d+", url) or
            re.search(r"bank|verify|update|secure|login|account|confirm", url, re.IGNORECASE) or
            re.search(r"\.(xyz|tk|ml|ga|cf|gq|top|buzz)$", url, re.IGNORECASE) or
            '@' in url
        )
        if is_suspicious:
            suspicious_set.add(url)

    return list(suspicious_set)


def extract_suspicious_keywords(text: str) -> list[str]:
    lower_text = text.lower()
    found = set()
    for keywords in SUSPICIOUS_KEYWORDS.values():
        for keyword in keywords:
            if contains_word(lower_text, keyword):
                found.add(keyword)
    return list(found)

# =========================
# 🔹 NEW: NER POST-PROCESS
# =========================

def ner_enrichment(text: str) -> dict:
    """
    Uses transformer NER to recover missed intel.
    NEVER replaces regex output.
    """
    ner_entities = extract_entities(text)
    enriched = defaultdict(list)

    for ent in ner_entities:
        label = ent["label"]
        value = ent["text"]

        digits = re.sub(r"\D", "", value)

        if label in ("NUM", "NUMBER"):
            if len(digits) == 10 and re.match(r"^[6-9]", digits):
                enriched["phoneNumbers"].append(digits)
            elif 9 <= len(digits) <= 18:
                enriched["bankAccounts"].append(digits)

        elif label == "MONEY":
            enriched["amounts"].append(value)

        elif label == "ORG":
            enriched["organizations"].append(value)

    return enriched

# =========================
# MAIN EXTRACTION (MERGED)
# =========================

def extract(text: str) -> dict:
    if not text:
        return {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": []
        }

    # 🔹 REGEX EXTRACTION (EXISTING)
    raw_accounts = extract_bank_accounts(text)
    raw_upis = extract_upi_ids(text)
    raw_phones = extract_phone_numbers(text)
    raw_links = extract_phishing_links(text)

    # 🔹 VALIDATION (EXISTING)
    from packages.domain.entities.validation_engine import IntelligenceValidator

    final_upis = [
        upi for upi in raw_upis
        if IntelligenceValidator.validate_upi_id(upi)["valid"]
    ]

    final_phones = [
        phone for phone in raw_phones
        if IntelligenceValidator.validate_phone(phone)["valid"]
    ]

    final_accounts = [
        acc for acc in raw_accounts
        if IntelligenceValidator.validate_bank_account(acc)["valid"]
    ]

    final_links = [
        link for link in raw_links
        if IntelligenceValidator.validate_url(link)["valid"]
    ]

    # 🔹 NEW: NER ENRICHMENT
    ner_data = ner_enrichment(text)

    # 🔹 MERGE (SAFE)
    result = {
        "bankAccounts": list(set(final_accounts + ner_data.get("bankAccounts", []))),
        "upiIds": final_upis,
        "phishingLinks": final_links,
        "phoneNumbers": list(set(final_phones + ner_data.get("phoneNumbers", []))),
        "suspiciousKeywords": extract_suspicious_keywords(text),
        # Optional metadata (safe to ignore elsewhere)
        "amounts": ner_data.get("amounts", []),
        "organizations": ner_data.get("organizations", [])
    }

    logger.debug(f"Extracted intel (merged): {result}")
    return result

# =========================
# SCORING (UNCHANGED)
# =========================

def get_scam_score(text: str) -> dict:
    intel = extract(text)
    score = 0
    breakdown = {}

    if intel["upiIds"]:
        score += 30
        breakdown["upiIds"] = 30
    if intel["phoneNumbers"]:
        score += 15
        breakdown["phoneNumbers"] = 15
    if intel["phishingLinks"]:
        score += 40
        breakdown["phishingLinks"] = 40
    if intel["suspiciousKeywords"]:
        keyword_score = min(len(intel["suspiciousKeywords"]) * 5, 30)
        score += keyword_score
        breakdown["keywords"] = keyword_score

    return {
        "score": min(score, 100),
        "breakdown": breakdown,
        "intelligence": intel
    }
