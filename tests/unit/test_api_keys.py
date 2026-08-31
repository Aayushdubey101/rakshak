"""Unit coverage for `packages/shared/security/api_keys.py` (task.md phase 14)."""

from packages.shared.security.api_keys import (
    ApiKeyPrincipal,
    SCOPE_ADMIN,
    SCOPE_ANALYZE,
    SCOPE_READ_INVESTIGATIONS,
    TOKEN_PREFIX,
    generate_api_key,
    hash_api_key,
)


def test_generated_key_has_the_expected_prefix_and_is_random():
    a, b = generate_api_key(), generate_api_key()
    assert a.startswith(TOKEN_PREFIX)
    assert b.startswith(TOKEN_PREFIX)
    assert a != b


def test_hash_is_deterministic_and_not_the_plaintext():
    plaintext = generate_api_key()
    assert hash_api_key(plaintext) == hash_api_key(plaintext)
    assert hash_api_key(plaintext) != plaintext


def test_admin_scope_grants_every_scope():
    principal = ApiKeyPrincipal(principal="root", scopes=frozenset({SCOPE_ADMIN}))
    assert principal.has_scope(SCOPE_ANALYZE)
    assert principal.has_scope(SCOPE_READ_INVESTIGATIONS)


def test_non_admin_scope_only_grants_itself():
    principal = ApiKeyPrincipal(principal="bot", scopes=frozenset({SCOPE_ANALYZE}))
    assert principal.has_scope(SCOPE_ANALYZE)
    assert not principal.has_scope(SCOPE_READ_INVESTIGATIONS)


def test_no_scopes_grants_nothing():
    principal = ApiKeyPrincipal(principal="nobody")
    assert not principal.has_scope(SCOPE_ANALYZE)
