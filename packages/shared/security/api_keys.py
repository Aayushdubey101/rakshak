"""Scoped API keys (task.md phase 14): "real accounts and API keys with
scopes... Retire the single shared secret."

A key's plaintext (`rak_<43 url-safe base64 chars>`, ~256 bits of entropy) is
shown exactly once, at creation. Only its sha256 hash is ever stored or
compared -- same principle as a password hash, simpler because there is
nothing here worth salting per-key (the token itself is the whole secret,
generated server-side, never user-chosen).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

TOKEN_PREFIX = "rak_"

# The five scopes task.md's phase 14 checklist names, verbatim.
SCOPE_ANALYZE = "analyze"
SCOPE_READ_INVESTIGATIONS = "read:investigations"
SCOPE_READ_THREAT_INTEL = "read:threat_intel"
SCOPE_RESEARCH_HONEYPOT = "research:honeypot"
SCOPE_ADMIN = "admin"

ALL_SCOPES = frozenset({
    SCOPE_ANALYZE, SCOPE_READ_INVESTIGATIONS, SCOPE_READ_THREAT_INTEL,
    SCOPE_RESEARCH_HONEYPOT, SCOPE_ADMIN,
})


def generate_api_key() -> str:
    return f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def hash_api_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ApiKeyPrincipal:
    """The authenticated caller. `key_id` is `None` for the legacy
    single-shared-secret fallback (no DB-backed key record to name)."""

    principal: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    key_id: str | None = None

    def has_scope(self, scope: str) -> bool:
        return SCOPE_ADMIN in self.scopes or scope in self.scopes
