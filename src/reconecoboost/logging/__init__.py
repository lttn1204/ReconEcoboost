"""Structured, correlated logging setup (architecture doc 14).

Note: this package is named ``logging`` to mirror the architecture layout.
Internal modules use absolute imports, so ``import logging`` inside this package
still resolves to the standard library, not this package.
"""

from .setup import configure_logging, get_logger

__all__ = ["configure_logging", "get_logger"]
