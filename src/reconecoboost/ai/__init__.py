"""AI provider abstraction (architecture doc 11).

Provider-agnostic interface + interchangeable adapters. Default: Claude. The
Stub provider runs offline (no network) for tests and confidential engagements.
"""

from .base import AIProvider, AIResponse
from .claude import ClaudeProvider
from .claude_code import ClaudeCodeProvider
from .factory import build_provider
from .stub import StubProvider

__all__ = [
    "AIProvider",
    "AIResponse",
    "ClaudeProvider",
    "ClaudeCodeProvider",
    "StubProvider",
    "build_provider",
]
