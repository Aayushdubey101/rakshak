from packages.shared.schemas.entities import EntityKind, ExtractedEntity
from packages.threat_intel.indicators import (
    hash_indicator,
    indicators_from_entities,
    normalize_indicator,
)


def test_phone_normalization_strips_formatting():
    assert normalize_indicator(EntityKind.PHONE, "+91 98765-43210") == "919876543210"


def test_domain_normalization_lowercases():
    assert normalize_indicator(EntityKind.DOMAIN, "SBI-Verify.XYZ") == "sbi-verify.xyz"


def test_same_indicator_hashes_identically_regardless_of_formatting():
    a = hash_indicator(EntityKind.PHONE, normalize_indicator(EntityKind.PHONE, "9876543210"))
    b = hash_indicator(EntityKind.PHONE, normalize_indicator(EntityKind.PHONE, "98765-43210"))
    assert a == b


def test_different_kinds_of_the_same_string_hash_differently():
    normalized = normalize_indicator(EntityKind.UPI_ID, "scammer@ybl")
    a = hash_indicator(EntityKind.UPI_ID, normalized)
    b = hash_indicator(EntityKind.ORGANIZATION, normalized)
    assert a != b


def test_indicators_from_entities_skips_noisy_kinds():
    entities = (
        ExtractedEntity(kind=EntityKind.UPI_ID, value="scammer@ybl", confidence=0.9, source="regex"),
        ExtractedEntity(kind=EntityKind.KEYWORD, value="urgent", confidence=0.5, source="regex"),
        ExtractedEntity(kind=EntityKind.PERSON, value="Rahul", confidence=0.5, source="ner"),
    )

    indicators = indicators_from_entities(entities)

    assert len(indicators) == 1
    assert indicators[0].kind == EntityKind.UPI_ID


def test_indicators_from_entities_dedupes_by_hash():
    entities = (
        ExtractedEntity(kind=EntityKind.PHONE, value="9876543210", confidence=0.9, source="regex"),
        ExtractedEntity(kind=EntityKind.PHONE, value="98765-43210", confidence=0.9, source="regex"),
    )

    indicators = indicators_from_entities(entities)

    assert len(indicators) == 1


def test_indicators_from_entities_uses_comparable_normalized_value_when_present():
    entity = ExtractedEntity(
        kind=EntityKind.URL, value="hxxp://scam[.]xyz/pay", normalized_value="http://scam.xyz/pay",
        confidence=0.9, source="ingestion",
    )

    indicators = indicators_from_entities((entity,))

    assert indicators[0].normalized == "http://scam.xyz/pay"
