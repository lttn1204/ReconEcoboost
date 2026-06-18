"""Prompt management (architecture doc 12).

Loads external Markdown prompt templates and renders them with a minimal
``{{ var }}`` substitution. Prompt contents live under the top-level ``prompts/``
tree, never in Python.
"""

from .manager import Prompt, PromptManager

__all__ = ["Prompt", "PromptManager"]
