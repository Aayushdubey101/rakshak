"""`ApiKeyRepository` Protocol. SQLAlchemy implementation lives in
`packages/shared/db/repositories.py`, same as every other repository in this
codebase -- an ORM session never appears above that file.
"""

from __future__ import annotations

from typing import Optional, Protocol

from packages.shared.security.api_keys import ApiKeyPrincipal


class ApiKeyRepository(Protocol):
    async def create(self, *, principal: str, scopes: frozenset[str]) -> tuple[str, str]:
        """Creates a key. Returns `(key_id, plaintext)` -- the plaintext is
        never retrievable again after this call returns."""
        ...

    async def verify(self, plaintext: str) -> Optional[ApiKeyPrincipal]:
        """`None` for missing, revoked, or unknown keys. A successful verify
        updates `last_used_at`."""
        ...

    async def revoke(self, key_id: str) -> bool:
        ...

    async def list_keys(self) -> list[dict]:
        ...
