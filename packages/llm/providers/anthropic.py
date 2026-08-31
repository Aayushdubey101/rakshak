"""Anthropic Messages API adapter.

Anthropic does not speak the OpenAI wire format, so it gets its own adapter
rather than a compatibility shim that would hide the differences.
"""

from __future__ import annotations

from typing import Any, Sequence

import httpx

from packages.llm.gateway.base import BaseProvider, LLMError, LLMResponse, TaskKind, Usage

ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MAX_TOKENS = 1024
_EXHAUSTED_STATUSES = frozenset({401, 402, 403, 429})


class AnthropicProvider(BaseProvider):
    capabilities = frozenset(
        {TaskKind.REASONING, TaskKind.FAST, TaskKind.STRUCTURED, TaskKind.VISION}
    )

    def __init__(
        self,
        *,
        base_url: str,
        model_id: str,
        credentials: Sequence[str],
        timeout_seconds: float = 20.0,
    ):
        super().__init__(credentials)
        self.name = "anthropic"
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _content(prompt: str, images: list[str] | None) -> Any:
        if not images:
            return prompt
        content: list[dict[str, Any]] = []
        for img in images:
            if isinstance(img, str) and img.startswith("data:"):
                try:
                    header, b64_data = img.split(",", 1)
                    media_type = header.split(";", 1)[0].removeprefix("data:")
                    content.append({
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": media_type,
                            "data": b64_data,
                        },
                    })
                except Exception:
                    pass
        content.append({"type": "text", "text": prompt})
        return content

    async def _generate_once(self, prompt: str, credential: str, **options: Any) -> LLMResponse:
        body: dict[str, Any] = {
            "model": options.get("model_id") or self.model_id,
            "max_tokens": options.get("max_tokens") or DEFAULT_MAX_TOKENS,
            "messages": [{"role": "user", "content": self._content(prompt, options.get("images"))}],
        }
        if options.get("temperature") is not None:
            body["temperature"] = options["temperature"]
        if options.get("json_mode"):
            # No response_format on this API; ask in-band, then parse defensively.
            body["system"] = "Reply with a single JSON object and nothing else."

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            response = await client.post(
                f"{self.base_url}/v1/messages",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": credential,
                    "anthropic-version": ANTHROPIC_VERSION,
                },
            )

        if response.status_code >= 400:
            raise LLMError(
                f"anthropic HTTP {response.status_code}: {response.text[:200]}",
                exhausted=response.status_code in _EXHAUSTED_STATUSES,
            )

        payload = response.json()
        blocks = payload.get("content") or []
        text = "".join(block.get("text", "") for block in blocks if isinstance(block, dict))
        if not text:
            raise LLMError("anthropic: empty content block")

        raw_usage = payload.get("usage") or {}
        return LLMResponse(
            text=text,
            provider=self.name,
            model_id=payload.get("model") or self.model_id,
            latency_ms=0,
            usage=Usage(
                requests=1,
                prompt_tokens=raw_usage.get("input_tokens", 0),
                completion_tokens=raw_usage.get("output_tokens", 0),
            ),
        )
