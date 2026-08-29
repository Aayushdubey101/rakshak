"""One place that knows whether Redis is configured.

No `REDIS_URL` means every caller below keeps its current in-process
fallback (plain dict, in-memory dedup set) — same DISABLED-not-a-stub
convention as the LLM providers. Configuring it is what makes session state,
rate limits, and webhook dedup shared across two API processes.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

import redis

from packages.shared.config.settings import get_settings


@lru_cache()
def get_redis_client() -> Optional["redis.Redis"]:
    url = get_settings().REDIS_URL
    if not url:
        return None
    return redis.Redis.from_url(url, decode_responses=True)


def reset_redis_client_cache() -> None:
    """Tests call this after monkeypatching REDIS_URL or injecting a fake client."""
    get_redis_client.cache_clear()
