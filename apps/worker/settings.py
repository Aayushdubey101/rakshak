"""arq worker entry point: `uv run arq apps.worker.settings.WorkerSettings`.

No new distributed infrastructure beyond Redis (task.md phase 13) -- one API
process, one worker process, the same Redis phase 7 already provisions.
"""

from __future__ import annotations

from arq.connections import RedisSettings

from apps.worker.tasks import MAX_TRIES, log_evidence, run_investigation
from packages.shared.config.settings import get_settings
from packages.shared.logging_config import configure_logging
from packages.shared.telemetry import configure_tracing


def _redis_settings() -> RedisSettings:
    url = get_settings().REDIS_URL
    return RedisSettings.from_dsn(url) if url else RedisSettings()


async def _on_startup(ctx: dict) -> None:
    # No uvicorn logging config to override here (unlike the API process),
    # so this runs directly at worker process startup, not deferred.
    configure_logging()
    configure_tracing()


class WorkerSettings:
    functions = [run_investigation, log_evidence]
    redis_settings = _redis_settings()
    max_tries = MAX_TRIES
    job_timeout = 60
    on_startup = _on_startup
