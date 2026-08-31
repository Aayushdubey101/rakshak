"""SessionStore (packages/shared/session_store.py) — the dict-like wrapper
session_manager.py's `sessions` module object is. Default (no client) must
behave exactly like the plain dict it replaces; the Redis-backed path (via
fakeredis, so no live server needed) is what makes two API processes share
sessions."""

import fakeredis

from packages.shared.session_store import SessionStore


def test_in_memory_backend_is_a_plain_dict_replacement():
    store = SessionStore()
    store["a"] = {"sessionId": "a", "n": 1}

    assert "a" in store
    assert store["a"] == {"sessionId": "a", "n": 1}
    assert store.get("b") is None
    assert len(store) == 1

    store.clear()
    assert "a" not in store
    assert len(store) == 0


def test_redis_backend_round_trips_json():
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    store = SessionStore(client)

    store["s1"] = {"sessionId": "s1", "conversationHistory": [{"sender": "x", "text": "hi"}]}

    assert "s1" in store
    assert store["s1"]["conversationHistory"][0]["sender"] == "x"


def test_redis_backend_is_shared_across_two_store_instances():
    """Two `SessionStore`s over the same client == two API processes."""
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    process_a = SessionStore(client)
    process_b = SessionStore(client)

    process_a["s1"] = {"sessionId": "s1", "messageCount": 1}

    assert process_b["s1"]["messageCount"] == 1


def test_redis_backend_clear_removes_only_its_own_keys():
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    store = SessionStore(client)
    client.set("unrelated:key", "untouched")

    store["s1"] = {"sessionId": "s1"}
    store.clear()

    assert "s1" not in store
    assert client.get("unrelated:key") == "untouched"


def test_missing_key_raises_key_error_both_backends():
    for store in (SessionStore(), SessionStore(fakeredis.FakeStrictRedis(decode_responses=True))):
        try:
            store["nope"]
            assert False, "expected KeyError"
        except KeyError:
            pass
