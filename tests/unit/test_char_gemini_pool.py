"""Golden output for GeminiPool. Records behavior as of phase 0.

Phase 3 generalizes this key-state machine into the LLM Gateway's fallback
policy rather than rewriting it, so its rules are pinned here: parse, failover
once per key, cooldown, and return None when everything is exhausted.

`google.generativeai` is replaced in-process — no network, no credentials.
"""

import asyncio
from types import SimpleNamespace

import pytest

from packages.llm.providers.gemini import pool as gp

pytestmark = pytest.mark.characterization


def _settings(**overrides) -> SimpleNamespace:
    base = dict(
        GEMINI_API_KEYS=None, GEMINI_API_KEY=None,
        GEMINI_API_KEY1=None, GEMINI_API_KEY2=None,
        GEMINI_API_KEY3=None, GEMINI_API_KEY4=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture
def pool(monkeypatch):
    """Build a GeminiPool over the given settings, with genai stubbed out."""
    def _build(**settings_overrides):
        monkeypatch.setattr(gp, "settings", _settings(**settings_overrides))
        return gp.GeminiPool()
    return _build


class FakeGenAI:
    """Stands in for the google.generativeai module."""

    def __init__(self, behavior):
        self.behavior = behavior  # key -> str | Exception
        self.configured: list[str] = []
        self._current = None

    def configure(self, api_key):
        self.configured.append(api_key)
        self._current = api_key

    def GenerativeModel(self, _name):  # noqa: N802 - mirrors the real API
        outcome = self.behavior[self._current]

        async def generate_content_async(_prompt):
            if isinstance(outcome, BaseException):
                raise outcome
            return SimpleNamespace(text=outcome)

        return SimpleNamespace(generate_content_async=generate_content_async)


# --- key parsing -------------------------------------------------------------

def test_comma_separated_keys_are_split_and_stripped(pool):
    assert pool(GEMINI_API_KEYS=" k1 , k2 ,, k3 ").keys == ["k1", "k2", "k3"]


def test_individual_keys_follow_the_comma_separated_ones(pool):
    p = pool(GEMINI_API_KEYS="k1", GEMINI_API_KEY2="k2", GEMINI_API_KEY4="k4")
    assert p.keys == ["k1", "k2", "k4"]


def test_duplicates_are_removed_in_order(pool):
    assert pool(GEMINI_API_KEYS="k1,k2", GEMINI_API_KEY1="k1").keys == ["k1", "k2"]


def test_legacy_single_key_is_only_a_last_resort(pool):
    assert pool(GEMINI_API_KEY="legacy").keys == ["legacy"]
    assert pool(GEMINI_API_KEYS="k1", GEMINI_API_KEY="legacy").keys == ["k1"]


def test_every_key_starts_available_with_a_five_minute_cooldown(pool):
    state = pool(GEMINI_API_KEYS="k1").key_states["k1"]
    assert state == {"available": True, "failed_at": None, "cooldown": 300}


# --- generation --------------------------------------------------------------

async def test_no_keys_returns_none_without_calling_the_provider(pool):
    assert await pool().generate_content("hi") is None


async def test_first_available_key_is_used(pool, monkeypatch):
    fake = FakeGenAI({"k1": "hello", "k2": "unused"})
    monkeypatch.setattr(gp, "genai", fake)
    p = pool(GEMINI_API_KEYS="k1,k2")

    assert await p.generate_content("hi") == "hello"
    assert fake.configured == ["k1"]


async def test_empty_model_text_is_returned_as_empty_string(pool, monkeypatch):
    monkeypatch.setattr(gp, "genai", FakeGenAI({"k1": ""}))
    assert await pool(GEMINI_API_KEYS="k1").generate_content("hi") == ""


async def test_quota_error_marks_the_key_and_fails_over(pool, monkeypatch):
    fake = FakeGenAI({"k1": Exception("429 quota exceeded"), "k2": "second"})
    monkeypatch.setattr(gp, "genai", fake)
    p = pool(GEMINI_API_KEYS="k1,k2")

    assert await p.generate_content("hi") == "second"
    assert fake.configured == ["k1", "k2"]
    assert p.key_states["k1"]["available"] is False
    assert p.key_states["k2"]["available"] is True


async def test_transient_error_does_not_disable_the_key(pool, monkeypatch):
    fake = FakeGenAI({"k1": Exception("connection reset"), "k2": "second"})
    monkeypatch.setattr(gp, "genai", fake)
    p = pool(GEMINI_API_KEYS="k1,k2")

    assert await p.generate_content("hi") == "second"
    assert p.key_states["k1"]["available"] is True


async def test_timeout_marks_the_key_unavailable(pool, monkeypatch):
    fake = FakeGenAI({"k1": asyncio.TimeoutError()})
    monkeypatch.setattr(gp, "genai", fake)
    p = pool(GEMINI_API_KEYS="k1")

    assert await p.generate_content("hi") is None
    assert p.key_states["k1"]["available"] is False


async def test_all_keys_failing_returns_none(pool, monkeypatch):
    fake = FakeGenAI({"k1": Exception("429"), "k2": Exception("quota")})
    monkeypatch.setattr(gp, "genai", fake)
    p = pool(GEMINI_API_KEYS="k1,k2")

    assert await p.generate_content("hi") is None
    assert all(s["available"] is False for s in p.key_states.values())


# --- cooldown ----------------------------------------------------------------

def test_failed_key_stays_unavailable_until_the_cooldown_expires(pool, monkeypatch):
    p = pool(GEMINI_API_KEYS="k1")
    monkeypatch.setattr(gp.time, "time", lambda: 1_000.0)
    p._mark_key_failed("k1")

    assert p._check_key_cooldown("k1") is False
    assert p._get_next_available_key() is None

    monkeypatch.setattr(gp.time, "time", lambda: 1_000.0 + 301)
    assert p._check_key_cooldown("k1") is True
    assert p.key_states["k1"]["failed_at"] is None


def test_unknown_key_is_never_available(pool):
    assert pool(GEMINI_API_KEYS="k1")._check_key_cooldown("nope") is False
