"""Webhook deduplication.

Telegram and WhatsApp both retry aggressively: a slow reply means the same
message arrives two or three times, and without this every retry would open a
second investigation and send a second answer.

No Redis configured -> in-memory and per-process, exactly as before. Redis
configured -> `SETNX`-with-TTL, atomic across every process sharing that
Redis, which is what phase 7 requires: the same webhook retry hitting two API
processes must still be recognized as a duplicate.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from threading import Lock
from typing import Any, Optional

DEFAULT_TTL_SECONDS = 900.0
DEFAULT_MAX_KEYS = 10_000
_KEY_PREFIX = "rakshak:dedup:"


class MessageDeduplicator:
    """Remembers platform message ids for a while. `seen()` is the whole API."""

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_keys: int = DEFAULT_MAX_KEYS,
        redis_client: Optional[Any] = None,
    ):
        self.ttl_seconds = ttl_seconds
        self.max_keys = max_keys
        self._keys: OrderedDict[str, float] = OrderedDict()
        self._lock = Lock()
        self._redis = redis_client

    def seen(self, platform: str, message_id: str) -> bool:
        """True if this message was already handled. Records it either way."""
        key = f"{platform}:{message_id}"
        if self._redis is not None:
            # SET NX is atomic: exactly one caller across every process gets
            # `True` (newly set) for a given key.
            newly_set = self._redis.set(_KEY_PREFIX + key, "1", nx=True, ex=int(self.ttl_seconds))
            return not bool(newly_set)

        now = time.time()
        with self._lock:
            self._evict(now)
            if key in self._keys:
                return True
            self._keys[key] = now
            while len(self._keys) > self.max_keys:
                self._keys.popitem(last=False)
            return False

    def _evict(self, now: float) -> None:
        cutoff = now - self.ttl_seconds
        while self._keys:
            key, stamp = next(iter(self._keys.items()))
            if stamp > cutoff:
                break
            self._keys.pop(key)

    def clear(self) -> None:
        if self._redis is not None:
            keys = list(self._redis.scan_iter(f"{_KEY_PREFIX}*"))
            if keys:
                self._redis.delete(*keys)
            return
        with self._lock:
            self._keys.clear()


# One per process unless Redis is configured, in which case every process
# sharing that Redis shares the dedup key set too.
from packages.shared.redis_client import get_redis_client  # noqa: E402

webhook_dedup = MessageDeduplicator(redis_client=get_redis_client())
