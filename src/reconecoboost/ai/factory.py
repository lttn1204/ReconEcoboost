"""Provider factory — selects the AI backend from configuration.

Switching providers is a config edit (``ai.yaml``), not a code change
(architecture doc 11). v1 ships Claude (default) and a Stub; other providers are
recognized names that raise until implemented.
"""

from __future__ import annotations

from typing import Any

from ..core.errors import AIError
from .base import AIProvider
from .claude import ClaudeProvider
from .claude_code import ClaudeCodeProvider
from .stub import StubProvider

_FUTURE = {"openai", "gemini", "ollama", "local"}


def build_provider(ai_config: dict[str, Any] | None = None) -> AIProvider:
    """Construct the configured :class:`AIProvider`."""
    config = ai_config or {}
    name = (config.get("provider") or "claude").lower()
    params = config.get("params", {})

    if name == "claude":
        return ClaudeProvider(
            model=config.get("model", "claude-opus-4-8"),
            max_tokens=int(params.get("max_tokens", 4096)),
            effort=params.get("effort", "high"),
        )
    if name in ("claude-code", "claude_code", "cc"):
        return ClaudeCodeProvider(
            model=config.get("model", "sonnet"),
            timeout_s=int(params.get("timeout_s", 300)),
        )
    if name in ("stub", "null"):
        return StubProvider()
    if name in _FUTURE:
        raise AIError(
            f"AI provider '{name}' is recognized but not implemented yet. "
            "Use 'claude' or 'stub'."
        )
    raise AIError(f"Unknown AI provider: '{name}'.")
