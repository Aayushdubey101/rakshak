"""RateLimitMiddleware (apps/api/middleware/rate_limit.py). No Redis
configured -> in-memory sliding window (today's behavior); Redis configured
(via fakeredis here) -> the shared-across-processes path phase 7 adds."""

import fakeredis
from starlette.requests import Request

from apps.api.middleware.rate_limit import RateLimitMiddleware
from packages.shared.security.api_keys import ApiKeyPrincipal, SCOPE_ANALYZE


def _middleware(**kwargs):
    async def app(scope, receive, send):
        pass

    return RateLimitMiddleware(app, requests_per_minute=3, **kwargs)


def test_in_memory_allows_up_to_the_limit_then_blocks():
    mw = _middleware()
    for _ in range(3):
        assert mw._check_in_memory("1.2.3.4") is True
    assert mw._check_in_memory("1.2.3.4") is False


def test_in_memory_tracks_ips_independently():
    mw = _middleware()
    for _ in range(3):
        mw._check_in_memory("1.1.1.1")
    assert mw._check_in_memory("2.2.2.2") is True


def test_redis_backend_allows_up_to_the_limit_then_blocks():
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    mw = _middleware(redis_client=client)

    for _ in range(3):
        assert mw._check_redis("1.2.3.4") is True
    assert mw._check_redis("1.2.3.4") is False


def test_redis_backend_is_shared_across_two_middleware_instances():
    """Two `RateLimitMiddleware`s over the same client == two API processes
    enforcing one combined limit."""
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    process_a = _middleware(redis_client=client)
    process_b = _middleware(redis_client=client)

    assert process_a._check_redis("1.2.3.4") is True
    assert process_a._check_redis("1.2.3.4") is True
    assert process_b._check_redis("1.2.3.4") is True  # 3rd request, still allowed
    assert process_b._check_redis("1.2.3.4") is False  # 4th, over the shared limit


def _request(*, principal=None, client_ip="9.9.9.9") -> Request:
    scope = {
        "type": "http", "method": "GET", "path": "/api/v1/investigations",
        "headers": [], "client": (client_ip, 12345),
    }
    request = Request(scope)
    if principal is not None:
        request.state.principal = principal
    return request


def test_rate_limit_key_uses_principal_when_authenticated():
    mw = _middleware()
    principal = ApiKeyPrincipal(principal="telegram-bot", scopes=frozenset({SCOPE_ANALYZE}), key_id="k1")

    assert mw._rate_limit_key(_request(principal=principal)) == "principal:k1"


def test_rate_limit_key_falls_back_to_ip_when_unauthenticated():
    mw = _middleware()

    assert mw._rate_limit_key(_request()) == "ip:9.9.9.9"
