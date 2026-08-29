"""One place that knows whether the arq job queue is configured.

Same DISABLED-not-a-stub convention as `redis_client.py`: no `REDIS_URL`
means `get_arq_pool()` returns `None`, and every caller degrades to running
the work inline instead of hard-failing. `create_pool()` is async (it pings
the connection), so this can't use `functools.lru_cache` like the sync redis
client does -- a module-level cache does the same job.
"""

from __future__ import annotations

from typing import Optional

from arq.connections import ArqRedis, RedisSettings, create_pool

from packages.shared.config.settings import get_settings

_pool: Optional[ArqRedis] = None


async def get_arq_pool() -> Optional[ArqRedis]:
    global _pool
    if _pool is not None:
        return _pool
    url = get_settings().REDIS_URL
    if not url:
        return None
    _pool = await create_pool(RedisSettings.from_dsn(url))
    return _pool


async def reset_arq_pool() -> None:
    """Tests call this after monkeypatching REDIS_URL or injecting a fake pool."""
    global _pool
    if _pool is not None:
        await _pool.close()
    _pool = None
