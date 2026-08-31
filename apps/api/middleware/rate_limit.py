from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from collections import defaultdict
import time
import uuid

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding 60s window, per principal when authenticated, per client IP
    otherwise (task.md phase 14: "Rate limiting per principal and per IP").

    `apps.api.middleware.auth.APIKeyMiddleware` runs first (it's added after
    this one in `main.py`, and Starlette's last-added middleware is
    outermost) and sets `request.state.principal` for every authenticated
    `/api/*` call before this dispatch runs -- so a caller with a real key is
    limited by *who* they are, not by an IP a NAT or proxy might share with
    other callers; an unauthenticated request (docs, static, a rejected auth
    attempt) still limits by IP.

    No Redis configured -> in-memory defaultdict, exactly today's behavior
    (and the only mode two API processes don't share limits in). Configured
    -> a Redis sorted set per key (ZADD/ZREMRANGEBYSCORE/ZCARD), so both
    processes see the same count. Swaps the store, not the dispatch logic.
    """

    def __init__(self, app, requests_per_minute=60, redis_client=None):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests = defaultdict(list)
        self._redis = redis_client

    def _rate_limit_key(self, request: Request) -> str:
        principal = getattr(request.state, "principal", None)
        if principal is not None:
            return f"principal:{principal.key_id or principal.principal}"
        client_ip = request.client.host if request.client else "unknown"
        return f"ip:{client_ip}"

    async def dispatch(self, request: Request, call_next):
        key = self._rate_limit_key(request)

        if self._redis is None:
            allowed = self._check_in_memory(key)
        else:
            allowed = self._check_redis(key)

        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                   "error": "Rate limit exceeded",
                   "message": "Please try again later"
                }
            )

        return await call_next(request)

    def _check_in_memory(self, key: str) -> bool:
        now = time.time()
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if now - req_time < 60
        ]
        if len(self.requests[key]) >= self.requests_per_minute:
            return False
        self.requests[key].append(now)
        return True

    def _check_redis(self, key: str) -> bool:
        redis_key = f"rakshak:ratelimit:{key}"
        now = time.time()
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, 0, now - 60)
        pipe.zcard(redis_key)
        _, count = pipe.execute()
        if count >= self.requests_per_minute:
            return False
        pipe = self._redis.pipeline()
        pipe.zadd(redis_key, {str(uuid.uuid4()): now})
        pipe.expire(redis_key, 60)
        pipe.execute()
        return True
