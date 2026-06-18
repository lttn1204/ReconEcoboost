"""AIProvider interface and response type.

The provider-agnostic contract the rest of the framework depends on. Callers
pass a rendered prompt and (optionally) a JSON schema; the adapter is
responsible for getting structured, validated output from its underlying model
and returning a uniform :class:`AIResponse` (architecture doc 11).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AIResponse:
    """Uniform result from any provider."""

    text: str
    parsed: dict[str, Any] | None = None  # populated when a schema was supplied
    model: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)


class AIProvider(ABC):
    """Interchangeable LLM backend. Switching providers is a config change."""

    @abstractmethod
    def generate(
        self,
        prompt: str,
        *,
        schema: dict[str, Any] | None = None,
        system: str | None = None,
        max_tokens: int | None = None,
        effort: str | None = None,
    ) -> AIResponse:
        """Run one completion. With ``schema``, return validated structured output."""

    def capabilities(self) -> dict[str, Any]:
        """Best-effort capability metadata (overridable)."""
        return {"structured_output": True, "streaming": False}
