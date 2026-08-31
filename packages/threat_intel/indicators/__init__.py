"""Normalize and hash the entities correlation and reputation key on.

Not every `ExtractedEntity` kind is worth correlating. A shared `KEYWORD`
("urgent", "verify") or `PERSON` name across two investigations is noise, not
evidence — scammers reuse scripts, not identities. A shared UPI ID, phone,
bank account, URL, domain, email, or organization name is a real link between
two investigations. `_CORRELATABLE_KINDS` is that allowlist.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from packages.shared.schemas.entities import EntityKind, ExtractedEntity

_CORRELATABLE_KINDS = frozenset({
    EntityKind.UPI_ID,
    EntityKind.PHONE,
    EntityKind.BANK_ACCOUNT,
    EntityKind.URL,
    EntityKind.DOMAIN,
    EntityKind.EMAIL,
    EntityKind.ORGANIZATION,
})

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class IndicatorKey:
    kind: EntityKind
    value: str
    normalized: str
    value_hash: str


def normalize_indicator(kind: EntityKind, value: str) -> str:
    """Per-kind normalization so the same real-world indicator hashes the
    same way regardless of formatting (`+91 98765-43210` vs `9876543210`,
    `SBI-Verify.XYZ` vs `sbi-verify.xyz`)."""
    if kind in (EntityKind.PHONE, EntityKind.BANK_ACCOUNT, EntityKind.UPI_ID):
        return _NON_ALNUM.sub("", value.lower())
    return value.strip().lower()


def hash_indicator(kind: EntityKind, normalized: str) -> str:
    return hashlib.sha256(f"{kind.value}:{normalized}".encode()).hexdigest()


def indicators_from_entities(entities: tuple[ExtractedEntity, ...]) -> tuple[IndicatorKey, ...]:
    """Deduplicates by hash — the same UPI ID mentioned twice in one message
    becomes one indicator, not two correlation calls."""
    seen: dict[str, IndicatorKey] = {}
    for entity in entities:
        if entity.kind not in _CORRELATABLE_KINDS:
            continue
        normalized = normalize_indicator(entity.kind, entity.comparable)
        if not normalized:
            continue
        value_hash = hash_indicator(entity.kind, normalized)
        if value_hash not in seen:
            seen[value_hash] = IndicatorKey(
                kind=entity.kind, value=entity.value, normalized=normalized, value_hash=value_hash,
            )
    return tuple(seen.values())
