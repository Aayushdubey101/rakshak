"""Golden output for intelligence_extractor + validation_engine.

All values captured from the current implementation. Several are wrong on
purpose — see the "known defect" comments. They are recorded so the phase 8
rewrite has to declare the change instead of drifting into it.
"""

import pytest

from packages.domain.entities import intelligence_extractor as ix
from packages.domain.entities.validation_engine import IntelligenceValidator

pytestmark = pytest.mark.characterization

MESSAGE_BANK = {
    "upi": "pay to fraudster@okaxis or backup@ybl",
    "phone": "call me on +919876543210 or 8123456789",
    "bank": "transfer to account 123456789012345",
    "url": "visit http://secure-bank-verify.xyz/login and bit.ly/abc123",
    "keywords": "urgent payment needed, verify your kyc now, you won a prize",
    "empty": "",
}

GOLDEN = {
    "upi": {
        "upiIds": ["backup@ybl", "fraudster@okaxis"],
        "phoneNumbers": [],
        "bankAccounts": [],
        "phishingLinks": [],
        "suspiciousKeywords": ["pay"],
        "score": 35,
    },
    "phone": {
        "upiIds": [],
        "phoneNumbers": ["8123456789", "9876543210"],
        # known defect: the +91-prefixed number is also captured as a 12-digit account
        "bankAccounts": ["919876543210"],
        "phishingLinks": [],
        "suspiciousKeywords": [],
        "score": 15,
    },
    "bank": {
        "upiIds": [],
        # known defect: a 10-digit window inside the 15-digit account reads as a phone
        "phoneNumbers": ["6789012345"],
        "bankAccounts": ["123456789012345"],
        "phishingLinks": [],
        "suspiciousKeywords": ["account", "transfer"],
        "score": 25,
    },
    "url": {
        "upiIds": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "phishingLinks": ["bit.ly/abc123", "http://secure-bank-verify.xyz/login"],
        "suspiciousKeywords": ["bank", "verify"],
        "score": 50,
    },
    "keywords": {
        "upiIds": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "phishingLinks": [],
        # "pay" dropped by the word-boundary fix (packages/domain/risk/keyword_match.py):
        # the text only contains "payment", and "pay" was previously a false
        # substring match inside it, not an independent word.
        "suspiciousKeywords": ["kyc", "now", "payment", "prize", "urgent", "verify", "won"],
        "score": 30,
    },
    "empty": {
        "upiIds": [],
        "phoneNumbers": [],
        "bankAccounts": [],
        "phishingLinks": [],
        "suspiciousKeywords": [],
        "score": 0,
    },
}


@pytest.mark.parametrize("name", sorted(MESSAGE_BANK))
@pytest.mark.parametrize(
    "field", ["upiIds", "phoneNumbers", "bankAccounts", "phishingLinks", "suspiciousKeywords"]
)
def test_extract_entity_sets(name, field):
    assert sorted(ix.extract(MESSAGE_BANK[name])[field]) == GOLDEN[name][field]


@pytest.mark.parametrize("name", sorted(MESSAGE_BANK))
def test_scam_score(name):
    assert ix.get_scam_score(MESSAGE_BANK[name])["score"] == GOLDEN[name]["score"]


def test_extract_empty_returns_five_buckets_only():
    """Empty input short-circuits before NER, so no amounts/organizations keys."""
    assert set(ix.extract("")) == {
        "bankAccounts", "upiIds", "phishingLinks", "phoneNumbers", "suspiciousKeywords"
    }


def test_extract_populated_adds_ner_metadata():
    assert set(ix.extract("pay to a@ybl")) == {
        "bankAccounts", "upiIds", "phishingLinks", "phoneNumbers",
        "suspiciousKeywords", "amounts", "organizations",
    }


def test_email_addresses_are_not_upi_ids():
    assert ix.extract_upi_ids("mail me at victim@gmail.com") == []


def test_upi_ids_are_lowercased_and_deduplicated():
    assert ix.extract_upi_ids("Fraud@OKAXIS and fraud@okaxis") == ["fraud@okaxis"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("+919876543210", ["9876543210"]),
        ("09876543210", ["9876543210"]),
        ("5123456789", []),  # must start 6-9
        ("98765", []),
    ],
)
def test_phone_normalization(text, expected):
    assert ix.extract_phone_numbers(text) == expected


def test_bank_accounts_skip_phones_and_dates():
    assert ix.extract_bank_accounts("call 9876543210 on 25121999") == []


def test_phishing_link_heuristics():
    """Flagged on shortener, IP host, credential keyword, or risky TLD."""
    for url in [
        "http://bit.ly/xyz123",
        "http://192.168.1.1/pay",
        "http://example.com/login",
        "http://cheap.xyz",
    ]:
        assert ix.extract_phishing_links(url), url
    assert ix.extract_phishing_links("https://www.wikipedia.org/") == []


# --- validation_engine -------------------------------------------------------

def test_validate_upi_known_handle_scores_higher():
    known = IntelligenceValidator.validate_upi_id("someone@okaxis")
    unknown = IntelligenceValidator.validate_upi_id("someone@randomhandle")
    assert (known["valid"], known["confidence"]) == (True, 0.95)
    assert (unknown["valid"], unknown["confidence"]) == (True, 0.7)
    assert IntelligenceValidator.validate_upi_id("not-a-upi")["valid"] is False


def test_validate_phone_rejects_repeating_digits():
    assert IntelligenceValidator.validate_phone("9876543210")["valid"] is True
    assert IntelligenceValidator.validate_phone("9999999999")["valid"] is False
    assert IntelligenceValidator.validate_phone("1234567890")["valid"] is False


def test_validate_bank_account_length_bounds():
    assert IntelligenceValidator.validate_bank_account("123456789")["valid"] is True
    assert IntelligenceValidator.validate_bank_account("12345678")["valid"] is False
    assert IntelligenceValidator.validate_bank_account("1" * 19)["valid"] is False


@pytest.mark.parametrize(
    "url,confidence",
    [
        ("http://192.168.0.1/pay", 0.9),
        ("http://cheap.xyz", 0.8),
        ("http://example.com/login", 0.7),
        ("http://bit.ly/x", 0.6),
        ("https://www.wikipedia.org/", 0.5),
    ],
)
def test_validate_url_confidence_ladder(url, confidence):
    result = IntelligenceValidator.validate_url(url)
    assert result["valid"] is True
    assert result["confidence"] == pytest.approx(confidence)


@pytest.mark.parametrize("value", ["", "   ", "not a url", "verify your account", "12345"])
def test_validate_url_rejects_non_urls(value):
    """Phase-0 fix: validate_url used to return valid=True for every input."""
    assert IntelligenceValidator.validate_url(value) == {
        "valid": False,
        "confidence": 0.0,
        "reason": "Not a URL",
    }
