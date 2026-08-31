"""LocalFileObjectStore (packages/shared/storage/object_store.py) — the
dev/test fallback used when S3_ENDPOINT_URL/S3_ACCESS_KEY aren't configured.
S3ObjectStore itself isn't exercised here: it needs a real S3/MinIO endpoint,
which this suite deliberately never touches (same zero-network convention as
everything else)."""

import pytest

from packages.shared.storage.object_store import LocalFileObjectStore


@pytest.fixture
def store(tmp_path):
    return LocalFileObjectStore(root=str(tmp_path))


async def test_put_then_get_round_trips(store):
    await store.put("screenshots/a.png", b"fake-png-bytes")
    assert await store.get("screenshots/a.png") == b"fake-png-bytes"


async def test_exists_reflects_put_and_delete(store):
    assert await store.exists("k") is False
    await store.put("k", b"data")
    assert await store.exists("k") is True
    await store.delete("k")
    assert await store.exists("k") is False


async def test_delete_of_missing_key_does_not_raise(store):
    await store.delete("never-existed")


async def test_path_traversal_key_is_rejected(store):
    with pytest.raises(ValueError):
        await store.put("../../etc/passwd", b"x")


async def test_nested_keys_create_their_own_directories(store):
    await store.put("a/b/c.txt", b"nested")
    assert await store.get("a/b/c.txt") == b"nested"
