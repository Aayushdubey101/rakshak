"""Phase 2: the API edge builds an InvestigationRequest from the legacy body.

The wire format is unchanged, so this adapter is the only place that knows the
old shape. Phase 5 adds one of these per channel; phase 6 makes all of them
call the same orchestrator.
"""

from datetime import datetime, timezone

import pytest

from apps.api.honeypot_adapter import HoneypotRequest, Message, to_investigation_request
from packages.shared.schemas import ContentType, Platform, parse_flexible_timestamp as _parse_timestamp


def _request(text="pay 500 to scammer@okaxis", timestamp=None, metadata=None) -> HoneypotRequest:
    return HoneypotRequest(
        sessionId="sess-1",
        message=Message(sender="scammer", text=text, timestamp=timestamp),
        metadata=metadata or {},
    )


def test_maps_the_legacy_body():
    investigation = to_investigation_request(_request())

    assert investigation.investigation_id.startswith("inv_")
    assert investigation.platform is Platform.API
    assert investigation.content_type is ContentType.TEXT
    assert investigation.text == "pay 500 to scammer@okaxis"
    assert investigation.media == () and investigation.urls == ()


def test_session_id_and_sender_move_into_metadata():
    """The honeypot session is a conversation, not a principal — it is not user_id."""
    investigation = to_investigation_request(_request(metadata={"channel": "sms"}))

    assert investigation.user_id is None
    assert investigation.metadata == {
        "session_id": "sess-1",
        "sender": "scammer",
        "channel": "sms",
    }


def test_each_request_gets_its_own_id():
    first, second = to_investigation_request(_request()), to_investigation_request(_request())
    assert first.investigation_id != second.investigation_id


def test_blank_text_cannot_form_an_investigation():
    """The router keeps answering; it just mints the id itself. See the API tests."""
    with pytest.raises(ValueError):
        to_investigation_request(_request(text="   "))


# --- timestamp normalization -------------------------------------------------

@pytest.mark.parametrize("value", [1_700_000_000, 1_700_000_000.0, "1700000000"])
def test_epoch_values_become_utc(value):
    assert _parse_timestamp(value) == datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)


def test_iso_string_without_zone_is_assumed_utc():
    assert _parse_timestamp("2026-08-08T10:30:00") == datetime(
        2026, 8, 8, 10, 30, tzinfo=timezone.utc
    )


def test_iso_string_keeps_its_zone():
    parsed = _parse_timestamp("2026-08-08T10:30:00+05:30")
    assert parsed.utcoffset().total_seconds() == 5.5 * 3600


@pytest.mark.parametrize("value", [None, "not a timestamp", {"nested": "thing"}])
def test_unusable_values_fall_back_to_now(value):
    assert _parse_timestamp(value).tzinfo is not None
