"""Integration-test isolation.

The evidence repository writes to the database; every test in this directory
gets an isolated in-memory sqlite (phase 7), reset here.
"""

import pytest

from packages.shared.db.engine import create_all, dispose_engine, reset_engine_cache
from packages.shared.db.repositories import reset_repository_cache


@pytest.fixture(autouse=True)
async def isolated_database():
    """A fresh in-memory database per test.

    `reset_engine_cache()` (no prior engine used yet — safe, nothing to
    dispose) drops the cached engine, so the next `get_engine()` call opens a
    brand new `sqlite+aiosqlite:///:memory:` — StaticPool keeps it alive for
    exactly this test. `dispose_engine()` on teardown closes that engine's
    connection-worker thread before dropping it; using `reset_engine_cache()`
    there instead leaked one aiosqlite thread per test. Repositories are also
    lru_cache'd on the (now-stale) session factory, so their cache needs
    clearing too or they'd keep querying the previous test's dead engine.
    """
    reset_engine_cache()
    reset_repository_cache()
    await create_all()
    yield
    await dispose_engine()
    reset_repository_cache()
