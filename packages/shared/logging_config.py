"""Structured JSON logging (task.md phase 15).

Every log line already carries `investigation_id` in its message text --
the orchestrator's own convention since phase 6. This formatter turns each
`LogRecord` into one JSON object per line, what a log aggregator (CloudWatch
Logs, the architecture doc's own observability stack) actually wants, and
promotes `investigation_id` to a top-level field via a contextvar so it can
be filtered/joined on without parsing the message text.

`configure_logging()` must run *after* uvicorn installs its own default
logging config (uvicorn.run() does this during server startup, before the
FastAPI lifespan runs) -- called from the app's `startup` event, not at
import time, so it overrides uvicorn's handlers instead of being overridden
by them. The worker has no such ordering constraint and calls it directly.
"""

from __future__ import annotations

import contextvars
import json
import logging
from datetime import datetime, timezone

investigation_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "investigation_id", default=None
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        investigation_id = investigation_id_var.get()
        if investigation_id is not None:
            payload["investigation_id"] = investigation_id
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(*, level: int = logging.INFO) -> None:
    """Installs the JSON formatter on the loggers this codebase actually
    writes to. Idempotent -- safe to call more than once."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "arq"):
        target = logging.getLogger(name)
        target.handlers = [handler]
        target.setLevel(level)
        target.propagate = False
