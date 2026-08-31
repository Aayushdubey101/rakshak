"""`SqlApiKeyRepository` against the real (test) database (task.md phase 14)."""

from packages.shared.db.repositories import get_api_key_repository
from packages.shared.security.api_keys import SCOPE_ANALYZE


async def test_a_created_key_verifies_with_its_scopes():
    repo = get_api_key_repository()
    key_id, plaintext = await repo.create(principal="telegram-bot", scopes=frozenset({SCOPE_ANALYZE}))

    principal = await repo.verify(plaintext)

    assert principal is not None
    assert principal.principal == "telegram-bot"
    assert principal.scopes == frozenset({SCOPE_ANALYZE})
    assert principal.key_id == key_id


async def test_verify_records_last_used_at():
    repo = get_api_key_repository()
    _, plaintext = await repo.create(principal="bot", scopes=frozenset({SCOPE_ANALYZE}))

    await repo.verify(plaintext)

    rows = await repo.list_keys()
    assert rows[0]["last_used_at"] is not None


async def test_unknown_key_does_not_verify():
    repo = get_api_key_repository()
    assert await repo.verify("rak_not-a-real-key") is None


async def test_revoked_key_no_longer_verifies():
    repo = get_api_key_repository()
    key_id, plaintext = await repo.create(principal="bot", scopes=frozenset({SCOPE_ANALYZE}))

    assert await repo.revoke(key_id) is True
    assert await repo.verify(plaintext) is None


async def test_revoking_twice_returns_false_the_second_time():
    repo = get_api_key_repository()
    key_id, _ = await repo.create(principal="bot", scopes=frozenset({SCOPE_ANALYZE}))

    assert await repo.revoke(key_id) is True
    assert await repo.revoke(key_id) is False
