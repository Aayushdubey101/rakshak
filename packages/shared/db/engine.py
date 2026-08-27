"""Async engine + session factory.

No `DATABASE_URL` configured means an in-process sqlite file under `data/` —
same DISABLED-not-a-stub convention as the LLM providers (phase 3) and the
Redis/object-storage clients below it (phase 7). Tests override
`DATABASE_URL` to `sqlite+aiosqlite:///:memory:` via `conftest.py` fixtures,
so the suite never touches a real Postgres.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from packages.shared.config.settings import get_settings
from packages.shared.db.models import Base

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _default_sqlite_url() -> str:
    import os

    os.makedirs("data", exist_ok=True)
    return "sqlite+aiosqlite:///data/rakshak.db"


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        url = get_settings().DATABASE_URL or _default_sqlite_url()
        if ":memory:" in url:
            # A fresh connection per pool checkout would mean a fresh (empty)
            # in-memory db each time. One shared connection is what makes
            # `sqlite+aiosqlite:///:memory:` usable at all — this is the
            # standard SQLAlchemy pattern for it, used only by tests here.
            _engine = create_async_engine(
                url, future=True, poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
        else:
            _engine = create_async_engine(url, future=True)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory


async def get_session() -> AsyncSession:
    """One session per unit of work. Caller is responsible for closing it."""
    return get_session_factory()()


async def create_all() -> None:
    """Create tables directly from metadata. Dev/test convenience only —
    real deployments migrate with Alembic (`migrations/`)."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def reset_engine_cache() -> None:
    """Drops the cached engine reference without disposing it. Only safe when
    the engine was never actually used (e.g. resetting before the first
    `create_all()` in a fresh test). Prefer `dispose_engine()` otherwise —
    dropping a used engine without disposing it leaks its connection-worker
    thread (aiosqlite runs one per engine)."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None


async def dispose_engine() -> None:
    """Disposes the current engine (closing its connection-worker thread)
    before dropping the cache. What test fixtures should call between tests,
    not `reset_engine_cache()` alone."""
    global _engine
    if _engine is not None:
        await _engine.dispose()
    reset_engine_cache()
