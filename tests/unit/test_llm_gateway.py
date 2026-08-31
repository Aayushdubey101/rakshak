"""Phase 3 contract tests for the LLM Gateway.

Zero network: HTTP providers are intercepted with respx, everything else uses
`tests/fakes.FakeProvider`. What these protect: ordered failover, per-credential
cooldown, config-driven routing, and the promise that losing every provider
degrades rather than raises at the call site.
"""

from types import SimpleNamespace

import httpx
import pytest
import respx

from packages.llm.gateway import (
    CredentialPool,
    LLMError,
    LLMGateway,
    NoProviderAvailable,
    ProviderStatus,
    TaskKind,
    parse_json_reply,
)
from packages.llm.providers import build_providers
from packages.llm.providers.anthropic import AnthropicProvider
from packages.llm.providers.openai_compatible import OpenAICompatibleProvider
from packages.llm.router.task_router import DEFAULT_CHAINS, TaskRouter, parse_task_routes
from tests.fakes import FakeProvider, always_failing


# --- CredentialPool ----------------------------------------------------------

def test_pool_rotates_and_deduplicates():
    pool = CredentialPool(["k1", "k2", "k1", ""])
    assert pool.credentials == ["k1", "k2"]
    assert [pool.next_available() for _ in range(4)] == ["k1", "k2", "k1", "k2"]


def test_empty_pool_is_falsy():
    pool = CredentialPool([])
    assert not pool
    assert pool.next_available() is None


def test_failed_credential_returns_after_its_cooldown(monkeypatch):
    import packages.llm.gateway.base as base

    pool = CredentialPool(["k1"], cooldown_seconds=300)
    monkeypatch.setattr(base.time, "time", lambda: 1_000.0)
    pool.mark_failed("k1")

    assert pool.available_count == 0
    assert pool.next_available() is None

    monkeypatch.setattr(base.time, "time", lambda: 1_301.0)
    assert pool.next_available() == "k1"


def test_success_clears_a_failure():
    pool = CredentialPool(["k1"])
    pool.mark_failed("k1")
    pool.mark_success("k1")
    assert pool.available_count == 1


# --- reply parsing -----------------------------------------------------------

@pytest.mark.parametrize(
    "reply",
    ['{"a": 1}', '```json\n{"a": 1}\n```', '```\n{"a": 1}\n```', '  {"a": 1}  '],
)
def test_parse_json_reply_unwraps_fences(reply):
    assert parse_json_reply(reply) == {"a": 1}


@pytest.mark.parametrize("reply", ["", "   ", "not json", "[1, 2]"])
def test_parse_json_reply_rejects_the_rest(reply):
    with pytest.raises(LLMError):
        parse_json_reply(reply)


# --- BaseProvider ------------------------------------------------------------

async def test_unconfigured_provider_is_disabled_and_never_called():
    provider = FakeProvider(configured=False)
    assert provider.health_check().status is ProviderStatus.DISABLED
    with pytest.raises(LLMError):
        await provider.generate("hi")
    assert provider.prompts == []


async def test_provider_fails_over_between_credentials():
    provider = FakeProvider(
        credentials=["k1", "k2"],
        replies=[LLMError("rate limited", exhausted=True), "second key worked"],
    )
    response = await provider.generate("hi")

    assert response.text == "second key worked"
    assert provider.calls == 2
    assert provider.usage().requests == 2 and provider.usage().failures == 1


async def test_exhausting_every_credential_cools_the_provider_down():
    provider = always_failing()
    with pytest.raises(LLMError):
        await provider.generate("hi")
    assert provider.health_check().status is ProviderStatus.COOLING_DOWN


async def test_structured_output_parses_the_reply():
    provider = FakeProvider(replies=['```json\n{"isScam": true}\n```'])
    assert await provider.structured_output("hi") == {"isScam": True}
    assert provider.options[0]["json_mode"] is True


async def test_default_stream_yields_the_whole_reply():
    provider = FakeProvider(replies=["one shot"])
    assert [chunk async for chunk in provider.stream("hi")] == ["one shot"]


# --- HTTP providers ----------------------------------------------------------

@respx.mock
async def test_openai_compatible_request_and_response():
    route = respx.post("https://api.example.test/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "model": "test-model",
                "choices": [{"message": {"content": "hello there"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            },
        )
    )
    provider = OpenAICompatibleProvider(
        "openai", base_url="https://api.example.test/v1", model_id="test-model",
        credentials=["k1"],
    )

    response = await provider.generate("say hi", temperature=0.2, json_mode=True)

    assert response.text == "hello there"
    assert (response.provider, response.model_id) == ("openai", "test-model")
    assert response.usage.prompt_tokens == 5

    request = route.calls[0].request
    assert request.headers["Authorization"] == "Bearer k1"
    body = request.read().decode()
    assert '"messages"' in body and '"response_format"' in body and '"temperature"' in body


@respx.mock
async def test_openai_compatible_rate_limit_exhausts_the_key():
    respx.post("https://api.example.test/v1/chat/completions").mock(
        return_value=httpx.Response(429, text="slow down")
    )
    provider = OpenAICompatibleProvider(
        "groq", base_url="https://api.example.test/v1", model_id="m", credentials=["k1"],
    )

    with pytest.raises(LLMError):
        await provider.generate("hi")
    assert provider.health_check().status is ProviderStatus.COOLING_DOWN


@respx.mock
async def test_ollama_style_provider_sends_no_authorization_header():
    route = respx.post("http://localhost:11434/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "hi"}}]})
    )
    provider = OpenAICompatibleProvider(
        "ollama", base_url="http://localhost:11434/v1", model_id="gemma3:4b",
        credentials=["-"], extra_body={"seed": 7},
    )

    assert (await provider.generate("hi")).text == "hi"
    request = route.calls[0].request
    assert "Authorization" not in request.headers
    assert '"seed"' in request.read().decode()


@respx.mock
async def test_anthropic_headers_and_content_blocks():
    route = respx.post("https://api.anthropic.test/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "model": "claude-sonnet-5",
                "content": [{"type": "text", "text": "part one "}, {"type": "text", "text": "two"}],
                "usage": {"input_tokens": 4, "output_tokens": 2},
            },
        )
    )
    provider = AnthropicProvider(
        base_url="https://api.anthropic.test", model_id="claude-sonnet-5", credentials=["k1"],
    )

    response = await provider.generate("hi")

    assert response.text == "part one two"
    assert response.usage.completion_tokens == 2
    headers = route.calls[0].request.headers
    assert headers["x-api-key"] == "k1"
    assert headers["anthropic-version"] == "2023-06-01"


# --- TaskRouter --------------------------------------------------------------

def _providers(*provs):
    return {p.name: p for p in provs}


def test_router_uses_the_default_chain_order():
    providers = _providers(FakeProvider("gemini"), FakeProvider("groq"))
    router = TaskRouter(providers)

    assert [p.name for p in router.resolve(TaskKind.REASONING)] == ["gemini", "groq"]
    assert DEFAULT_CHAINS[TaskKind.FAST][0] == "groq"
    assert [p.name for p in router.resolve(TaskKind.FAST)] == ["groq", "gemini"]


def test_router_skips_disabled_and_incapable_providers():
    providers = _providers(
        FakeProvider("gemini", configured=False),
        FakeProvider("groq", capabilities=frozenset({TaskKind.FAST})),
        FakeProvider("openai"),
    )
    router = TaskRouter(providers)

    assert [p.name for p in router.resolve(TaskKind.REASONING)] == ["openai"]
    assert [p.name for p in router.resolve(TaskKind.FAST)] == ["groq", "openai"]


def test_preferred_provider_goes_first():
    providers = _providers(FakeProvider("gemini"), FakeProvider("ollama"))
    router = TaskRouter(providers, preferred="ollama")
    assert [p.name for p in router.resolve(TaskKind.REASONING)] == ["ollama", "gemini"]


def test_task_routes_override_the_defaults():
    providers = _providers(FakeProvider("gemini"), FakeProvider("ollama"))
    router = TaskRouter(providers, overrides=parse_task_routes('{"reasoning": ["ollama"]}'))
    assert [p.name for p in router.resolve(TaskKind.REASONING)] == ["ollama"]


@pytest.mark.parametrize("raw", [None, "", "   ", "{not json", '{"nope": ["x"]}'])
def test_unusable_task_routes_fall_back_to_defaults(raw):
    assert parse_task_routes(raw) == {}


def test_task_routes_accept_a_bare_string():
    assert parse_task_routes('{"fast": "groq"}') == {TaskKind.FAST: ("groq",)}


# --- LLMGateway --------------------------------------------------------------

def _gateway(*provs, **router_kwargs) -> LLMGateway:
    providers = _providers(*provs)
    return LLMGateway(providers, TaskRouter(providers, **router_kwargs))


async def test_gateway_returns_the_first_provider_that_answers():
    gemini, groq = always_failing("gemini"), FakeProvider("groq", replies=["from groq"])
    gateway = _gateway(gemini, groq)

    response = await gateway.generate(TaskKind.REASONING, "why?")

    assert (response.text, response.provider) == ("from groq", "groq")
    assert gemini.calls == 1


async def test_gateway_raises_when_nothing_is_configured():
    gateway = _gateway(FakeProvider("gemini", configured=False))
    with pytest.raises(NoProviderAvailable):
        await gateway.generate(TaskKind.REASONING, "why?")


async def test_gateway_raises_when_every_provider_fails():
    gateway = _gateway(always_failing("gemini"), always_failing("groq"))
    with pytest.raises(NoProviderAvailable):
        await gateway.generate(TaskKind.REASONING, "why?")


async def test_try_generate_degrades_instead_of_raising():
    gateway = _gateway(always_failing("gemini"))
    assert await gateway.try_generate(TaskKind.REASONING, "why?") is None


async def test_has_provider_for_reports_availability():
    gateway = _gateway(FakeProvider("gemini", capabilities=frozenset({TaskKind.VISION})))
    assert gateway.has_provider_for(TaskKind.VISION) is True
    assert gateway.has_provider_for(TaskKind.REASONING) is False


async def test_gateway_structured_output():
    gateway = _gateway(FakeProvider("gemini", replies=['{"verdict": "scam"}']))
    assert await gateway.structured_output(TaskKind.STRUCTURED, "classify") == {"verdict": "scam"}


async def test_gateway_aggregates_usage_and_health():
    good, bad = FakeProvider("gemini", replies=["ok"]), always_failing("groq")
    gateway = _gateway(good, bad)

    await gateway.try_generate(TaskKind.REASONING, "hi")
    await gateway.try_generate(TaskKind.FAST, "hi")  # groq first, then gemini

    usage = gateway.usage()
    assert usage.requests >= 2 and usage.failures >= 1
    statuses = {h.name: h.status for h in gateway.health()}
    assert statuses["gemini"] is ProviderStatus.READY
    assert statuses["groq"] is ProviderStatus.COOLING_DOWN


# --- registry ----------------------------------------------------------------

def _settings(**overrides) -> SimpleNamespace:
    base = dict(
        LLM_TIMEOUT_SECONDS=5.0, LLM_SEED=None,
        OLLAMA_ENABLED=False, OLLAMA_BASE_URL="http://localhost:11434/v1",
        OLLAMA_MODEL="gemma3:4b",
        OPENAI_API_KEY=None, OPENAI_BASE_URL="https://api.openai.com/v1",
        OPENAI_MODEL="gpt-4o-mini",
        ANTHROPIC_API_KEY=None, ANTHROPIC_BASE_URL="https://api.anthropic.com",
        ANTHROPIC_MODEL="claude-sonnet-5",
        GROQ_API_KEY=None, GROQ_BASE_URL="https://api.groq.com/openai/v1",
        GROQ_MODEL="llama-3.3-70b-versatile",
        OPENROUTER_API_KEY=None, OPENROUTER_BASE_URL="https://openrouter.ai/api/v1",
        OPENROUTER_MODEL="openrouter/auto",
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_registry_builds_every_provider():
    providers = build_providers(_settings())
    assert set(providers) == {"gemini", "ollama", "openai", "anthropic", "groq", "openrouter"}


def test_unconfigured_providers_report_disabled_rather_than_raising():
    providers = build_providers(_settings())
    # tests/conftest.py blanks every credential, so nothing is configured here.
    assert all(p.health_check().status is ProviderStatus.DISABLED for p in providers.values())


def test_ollama_is_opt_in():
    assert build_providers(_settings())["ollama"].health_check().status is ProviderStatus.DISABLED
    enabled = build_providers(_settings(OLLAMA_ENABLED=True))["ollama"]
    assert enabled.health_check().status is ProviderStatus.READY


def test_comma_separated_keys_become_separate_credentials():
    provider = build_providers(_settings(OPENAI_API_KEY="k1, k2"))["openai"]
    assert provider.health_check().available_credentials == 2
