"""Dict-shaped storage for honeypot session state.

`session_manager.py`'s functions only ever do `sessions[id]`, `sessions.get(id)`,
`id in sessions`, `sessions[id] = ...`, and (from tests) `sessions.clear()`.
This class supports exactly that surface, so swapping the backend needs no
change at any call site — same "swap the store, not the call sites" pattern
already used for `packages/shared/dedup.py`.

No Redis configured -> plain dict, byte-for-byte today's behavior. Configured
-> JSON blobs in Redis, so two API processes see the same session.

ponytail: `.clear()` on the Redis backend does a SCAN + DELETE per key. Fine
for a dev/test reset; a session count in the millions would want a Redis
`SELECT`-ed keyspace + `FLUSHDB` instead.
"""

from __future__ import annotations

import json
from typing import Any, Iterator, MutableMapping, Optional

_KEY_PREFIX = "rakshak:session:"


class SessionStore(MutableMapping[str, dict]):
    def __init__(self, redis_client: Optional[Any] = None, *, ttl_seconds: int = 60 * 60 * 24):
        self._redis = redis_client
        self._local: dict[str, dict] = {}
        self.ttl_seconds = ttl_seconds

    def __getitem__(self, session_id: str) -> dict:
        if self._redis is None:
            return self._local[session_id]
        raw = self._redis.get(_KEY_PREFIX + session_id)
        if raw is None:
            raise KeyError(session_id)
        return json.loads(raw)

    def __setitem__(self, session_id: str, session: dict) -> None:
        if self._redis is None:
            self._local[session_id] = session
            return
        self._redis.set(_KEY_PREFIX + session_id, json.dumps(session), ex=self.ttl_seconds)

    def __delitem__(self, session_id: str) -> None:
        if self._redis is None:
            del self._local[session_id]
            return
        self._redis.delete(_KEY_PREFIX + session_id)

    def __contains__(self, session_id: object) -> bool:
        if self._redis is None:
            return session_id in self._local
        return bool(self._redis.exists(_KEY_PREFIX + str(session_id)))

    def __iter__(self) -> Iterator[str]:
        if self._redis is None:
            return iter(self._local)
        prefix_len = len(_KEY_PREFIX)
        return (key[prefix_len:] for key in self._redis.scan_iter(f"{_KEY_PREFIX}*"))

    def __len__(self) -> int:
        if self._redis is None:
            return len(self._local)
        return sum(1 for _ in self)

    def clear(self) -> None:
        if self._redis is None:
            self._local.clear()
            return
        keys = list(self._redis.scan_iter(f"{_KEY_PREFIX}*"))
        if keys:
            self._redis.delete(*keys)
