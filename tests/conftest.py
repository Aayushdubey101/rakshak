"""Test environment. Must run before any `app.*` import.

`app/models/hf_models.py` loads Hugging Face pipelines at import time and
`app/config/config.py` requires API_SECRET_KEY, so both are pinned here.
"""

import os

os.environ.setdefault("API_SECRET_KEY", "test_secret_key")
os.environ.setdefault("DEPLOYMENT_MODE", "lite")  # no model downloads in CI
os.environ.setdefault("HF_LITE_MODE", "true")
os.environ.setdefault("STRICT_RESPONSE_MODE", "true")
# In-memory + StaticPool (packages/shared/db/engine.py): zero network, zero
# state left on disk. tests/integration/conftest.py resets it per test.
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
# Blanked, not popped: Settings still reads `.env`, and a real key there would
# make the test suite call the live Gemini API. Env vars win over `.env`.
for _k in ("GEMINI_API_KEY", "GEMINI_API_KEYS", "GEMINI_API_KEY1",
           "GEMINI_API_KEY2", "GEMINI_API_KEY3", "GEMINI_API_KEY4"):
    os.environ[_k] = ""
# Same reasoning, Ollama's turn: a developer's local `.env` may set
# OLLAMA_ENABLED=true for real manual testing against a running Ollama
# server. Left on here, ai_based_detection() calls a real local LLM during
# the test suite -- non-deterministic verdicts (a real model, unlike the
# deterministic no-provider fallback, can flag a benign golden case) and a
# ~20x slower run. Forced off, matching this file's own "zero network calls"
# contract for the whole suite.
os.environ["OLLAMA_ENABLED"] = "false"

import random  # noqa: E402

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_state():
    """Module-level singletons leak across tests. Reset the mutable ones."""
    from packages.agents.honeypot import emotion_engine
    from packages.domain.investigations import session_manager
    from packages.agents.honeypot.response_memory import response_memory

    session_manager.sessions.clear()
    response_memory.memory.clear()
    emotion_engine.emotion_tracker.clear()
    random.seed(1337)
    yield
    session_manager.sessions.clear()


@pytest.fixture
def settings():
    from packages.shared.config.settings import get_settings

    return get_settings()
