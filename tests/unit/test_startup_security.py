"""Unit coverage for `apps/api/main.py`'s `_assert_production_security()`
(task.md phase 14: "fail loudly on a missing required secret" / webhook
verification "mandatory... in production").
"""

from types import SimpleNamespace

import pytest

from apps.api.main import _assert_production_security


def _settings(**overrides) -> SimpleNamespace:
    base = dict(
        ENVIRONMENT="production",
        HONEYPOT_ENABLED=False,
        HONEYPOT_RESEARCHER_KEY=None,
        TELEGRAM_BOT_TOKEN=None,
        TELEGRAM_WEBHOOK_SECRET=None,
        WHATSAPP_ACCESS_TOKEN=None,
        WHATSAPP_APP_SECRET=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_development_never_raises_regardless_of_gaps():
    _assert_production_security(_settings(ENVIRONMENT="development", HONEYPOT_ENABLED=True))


def test_production_with_nothing_configured_is_fine():
    _assert_production_security(_settings())


def test_production_honeypot_enabled_without_researcher_key_raises():
    with pytest.raises(RuntimeError, match="HONEYPOT_RESEARCHER_KEY"):
        _assert_production_security(_settings(HONEYPOT_ENABLED=True))


def test_production_telegram_token_without_webhook_secret_raises():
    with pytest.raises(RuntimeError, match="TELEGRAM_WEBHOOK_SECRET"):
        _assert_production_security(_settings(TELEGRAM_BOT_TOKEN="abc"))


def test_production_whatsapp_token_without_app_secret_raises():
    with pytest.raises(RuntimeError, match="WHATSAPP_APP_SECRET"):
        _assert_production_security(_settings(WHATSAPP_ACCESS_TOKEN="abc"))


def test_production_fully_configured_is_fine():
    _assert_production_security(_settings(
        HONEYPOT_ENABLED=True, HONEYPOT_RESEARCHER_KEY="k",
        TELEGRAM_BOT_TOKEN="t", TELEGRAM_WEBHOOK_SECRET="s",
        WHATSAPP_ACCESS_TOKEN="w", WHATSAPP_APP_SECRET="ws",
    ))
