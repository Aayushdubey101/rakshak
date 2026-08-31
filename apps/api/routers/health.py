"""Liveness/readiness (task.md phase 15).

Two different questions, two different endpoints, matching the ECS/ALB
distinction the deployment diagram implies:

* `/health/live` -- is the process up at all? No dependency checks. This is
  what an ECS task-level health check watches; failing it kills and restarts
  the task, so it must never fail because Postgres is slow.
* `/health/ready` -- should this instance receive traffic? Checked by the
  ALB target group. A dependency being down degrades the response body, it
  never raises -- same "always answer" contract the rest of this codebase
  uses for LLM providers, object storage, and Redis.
"""

from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Response
from sqlalchemy import text

from packages.llm.gateway.gateway import get_gateway
from packages.shared.db.engine import get_engine
from packages.shared.redis_client import get_redis_client
from packages.shared.storage.object_store import get_object_store

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live")
def liveness() -> dict:
    return {"status": "ok"}


async def _check_database() -> str:
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return "ok"
    except Exception as exc:
        return f"error: {exc}"[:200]


async def _check_redis() -> str:
    client = get_redis_client()
    if client is None:
        return "disabled"
    try:
        await asyncio.to_thread(client.ping)
        return "ok"
    except Exception as exc:
        return f"error: {exc}"[:200]


async def _check_object_storage() -> str:
    try:
        await get_object_store().exists("healthcheck-probe")
        return "ok"
    except Exception as exc:
        return f"error: {exc}"[:200]


def _check_llm_providers() -> dict:
    return {health.name: health.status.value for health in get_gateway().health()}


@router.get("/ready")
async def readiness(response: Response) -> dict:
    database, redis_status, storage = await asyncio.gather(
        _check_database(), _check_redis(), _check_object_storage()
    )
    checks = {
        "database": database,
        "redis": redis_status,
        "object_storage": storage,
        "llm_providers": _check_llm_providers(),
    }
    # Redis and individual LLM providers degrade a report rather than block
    # one (same rule everywhere else in this codebase); the database and
    # object storage are load-bearing for every request that writes state.
    # Unlike every other "always answer" endpoint in this codebase, a
    # readiness probe's whole job is to be a routing signal -- the ALB
    # target group (infra/terraform/alb.tf) only stops sending traffic here
    # if this isn't a 200, so a degraded body still needs a non-200 status.
    critical_ok = database == "ok" and storage == "ok"
    if not critical_ok:
        response.status_code = 503
    return {
        "status": "ready" if critical_ok else "degraded",
        "checks": checks,
        "timestamp": time.time(),
    }
