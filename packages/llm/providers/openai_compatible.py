"""One adapter for every OpenAI-compatible endpoint.

OpenAI, Groq, OpenRouter, and Ollama all speak `/chat/completions` with the same
request and response shape. They differ in base URL, model id, and auth — so
they are configurations of this class, not four hand-written adapters.

These are real adapters, not stubs: an unconfigured one reports DISABLED and the
router skips it, but a configured one talks to its endpoint.
"""

from __future__ import annotations

from typing import Any, Sequence

import httpx

from packages.llm.gateway.base import BaseProvider, LLMError, LLMResponse, TaskKind, Usage

# Statuses where retrying the same credential is pointless.
_EXHAUSTED_STATUSES = frozenset({401, 402, 403, 429})


class OpenAICompatibleProvider(BaseProvider):
    def __init__(
        self,
        name: str,
        *,
        base_url: str,
        model_id: str,
        credentials: Sequence[str],
        timeout_seconds: float = 20.0,
        capabilities: frozenset[TaskKind] | None = None,
        extra_headers: dict[str, str] | None = None,
        extra_body: dict[str, Any] | None = None,
    ):
        super().__init__(credentials)
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.timeout_seconds = timeout_seconds
        self.extra_headers = extra_headers or {}
        self.extra_body = extra_body or {}
        if capabilities is not None:
            self.capabilities = capabilities

    def _headers(self, credential: str) -> dict[str, str]:
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if credential and credential != "-":
            headers["Authorization"] = f"Bearer {credential}"
        return headers

    @staticmethod
    def _content(prompt: str, images: list[str] | None) -> Any:
        """Plain string, or multimodal parts when images come along."""
        if not images:
            return prompt
        return [
            {"type": "text", "text": prompt},
            *({"type": "image_url", "image_url": {"url": url}} for url in images),
        ]

    async def _generate_once(self, prompt: str, credential: str, **options: Any) -> LLMResponse:
        body: dict[str, Any] = {
            "model": options.get("model_id") or self.model_id,
            "messages": [
                {"role": "user", "content": self._content(prompt, options.get("images"))}
            ],
            **self.extra_body,
        }
        if options.get("temperature") is not None:
            body["temperature"] = options["temperature"]
        if options.get("max_tokens") is not None:
            body["max_tokens"] = options["max_tokens"]
        if options.get("json_mode"):
            body["response_format"] = {"type": "json_object"}

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                json=body,
                headers=self._headers(credential),
            )

        if response.status_code >= 400:
            raise LLMError(
                f"{self.name} HTTP {response.status_code}: {response.text[:200]}",
                exhausted=response.status_code in _EXHAUSTED_STATUSES,
            )

        payload = response.json()
        try:
            text = payload["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"{self.name}: unexpected response shape ({exc})") from exc

        raw_usage = payload.get("usage") or {}
        return LLMResponse(
            text=text,
            provider=self.name,
            model_id=payload.get("model") or self.model_id,
            latency_ms=0,  # measured by BaseProvider.generate
            usage=Usage(
                requests=1,
                prompt_tokens=raw_usage.get("prompt_tokens", 0),
                completion_tokens=raw_usage.get("completion_tokens", 0),
            ),
        )
