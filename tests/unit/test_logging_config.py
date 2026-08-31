"""JSON log formatter + investigation_id correlation (task.md phase 15)."""

import json
import logging

from packages.shared.logging_config import JsonFormatter, investigation_id_var


def _record(message: str, level: int = logging.INFO) -> logging.LogRecord:
    return logging.LogRecord(
        name="uvicorn", level=level, pathname=__file__, lineno=1,
        msg=message, args=(), exc_info=None,
    )


def test_formats_a_record_as_one_json_object():
    payload = json.loads(JsonFormatter().format(_record("hello")))
    assert payload["level"] == "INFO"
    assert payload["logger"] == "uvicorn"
    assert payload["message"] == "hello"
    assert "timestamp" in payload
    assert "investigation_id" not in payload


def test_promotes_the_current_investigation_id_to_a_top_level_field():
    token = investigation_id_var.set("inv-123")
    try:
        payload = json.loads(JsonFormatter().format(_record("stage ok")))
    finally:
        investigation_id_var.reset(token)
    assert payload["investigation_id"] == "inv-123"
