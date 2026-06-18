"""Claude (Anthropic) provider adapter.

Uses the official ``anthropic`` SDK (imported lazily so the package isn't a hard
dependency until the provider is actually used). Defaults to Claude Opus 4.8
with adaptive thinking. Structured output is requested via
``output_config.format`` and validated by parsing the returned JSON.

Note: Opus 4.8 rejects ``temperature``/``top_p``/``budget_tokens`` — this
adapter never sends them. Depth is controlled by ``effort`` (architecture doc 11,
Claude API reference).
"""

from __future__ import annotations

import json
from typing import Any

from ..core.errors import AIError
from .base import AIProvider, AIResponse

DEFAULT_MODEL = "claude-opus-4-8"
DEFAULT_MAX_TOKENS = 4096


class ClaudeProvider(AIProvider):
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        effort: str | None = "high",
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self._client = None  # lazily constructed

    def _get_client(self):
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover - environment dependent
                raise AIError(
                    "The 'anthropic' package is required for the Claude provider. "
                    "Install it with 'pip install anthropic'."
                ) from exc
            # Resolves ANTHROPIC_API_KEY from the environment.
            self._client = anthropic.Anthropic()
        return self._client

    def generate(
        self,
        prompt: str,
        *,
        schema: dict[str, Any] | None = None,
        system: str | None = None,
        max_tokens: int | None = None,
        effort: str | None = None,
    ) -> AIResponse:
        client = self._get_client()

        output_config: dict[str, Any] = {}
        if schema is not None:
            output_config["format"] = {"type": "json_schema", "schema": schema}
        eff = effort or self.effort
        if eff:
            output_config["effort"] = eff

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "thinking": {"type": "adaptive"},
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            kwargs["system"] = system
        if output_config:
            kwargs["output_config"] = output_config

        try:
            response = client.messages.create(**kwargs)
        except Exception as exc:  # surface SDK/API errors as a typed AIError
            raise AIError(f"Claude request failed: {exc}") from exc

        if getattr(response, "stop_reason", None) == "refusal":
            raise AIError("Claude refused the request (stop_reason=refusal).")

        text = next((b.text for b in response.content if b.type == "text"), "")
        parsed = None
        if schema is not None and text:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError as exc:
                raise AIError(f"Claude returned non-JSON for a schema request: {exc}") from exc

        usage = {}
        if getattr(response, "usage", None) is not None:
            usage = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }

        return AIResponse(text=text, parsed=parsed, model=response.model, usage=usage)
