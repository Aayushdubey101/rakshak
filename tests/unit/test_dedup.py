"""Webhook deduplication.

Both platforms redeliver on any slow or non-2xx response. Without this, one slow
investigation becomes three investigations and three replies.
"""

from packages.shared.dedup import MessageDeduplicator


def test_first_sighting_is_new_and_the_second_is_not():
    dedup = MessageDeduplicator()
    assert dedup.seen("telegram", "42") is False
    assert dedup.seen("telegram", "42") is True


def test_platforms_do_not_share_a_namespace():
    dedup = MessageDeduplicator()
    dedup.seen("telegram", "42")
    assert dedup.seen("whatsapp", "42") is False


def test_entries_expire(monkeypatch):
    import packages.shared.dedup as module

    dedup = MessageDeduplicator(ttl_seconds=100)
    monkeypatch.setattr(module.time, "time", lambda: 1_000.0)
    dedup.seen("telegram", "42")

    monkeypatch.setattr(module.time, "time", lambda: 1_101.0)
    assert dedup.seen("telegram", "42") is False


def test_the_key_set_is_bounded():
    dedup = MessageDeduplicator(max_keys=3)
    for i in range(10):
        dedup.seen("telegram", str(i))

    assert len(dedup._keys) == 3
    assert dedup.seen("telegram", "9") is True   # newest kept
    assert dedup.seen("telegram", "0") is False  # oldest evicted


def test_clear_forgets_everything():
    dedup = MessageDeduplicator()
    dedup.seen("telegram", "42")
    dedup.clear()
    assert dedup.seen("telegram", "42") is False


# --- Redis-backed (phase 7): shared across processes -------------------------

def test_redis_backend_first_sighting_is_new_and_the_second_is_not():
    import fakeredis

    client = fakeredis.FakeStrictRedis(decode_responses=True)
    dedup = MessageDeduplicator(redis_client=client)

    assert dedup.seen("telegram", "42") is False
    assert dedup.seen("telegram", "42") is True


def test_redis_backend_is_shared_across_two_deduplicator_instances():
    """Two `MessageDeduplicator`s over the same client == two API processes
    catching the same webhook retry."""
    import fakeredis

    client = fakeredis.FakeStrictRedis(decode_responses=True)
    process_a = MessageDeduplicator(redis_client=client)
    process_b = MessageDeduplicator(redis_client=client)

    assert process_a.seen("telegram", "42") is False
    assert process_b.seen("telegram", "42") is True


def test_redis_backend_clear_forgets_everything():
    import fakeredis

    client = fakeredis.FakeStrictRedis(decode_responses=True)
    dedup = MessageDeduplicator(redis_client=client)
    dedup.seen("telegram", "42")

    dedup.clear()

    assert dedup.seen("telegram", "42") is False
