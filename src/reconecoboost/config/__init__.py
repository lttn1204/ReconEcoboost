"""Configuration layer: layered, concern-split YAML loaded into typed objects.

See architecture doc 13. Merge precedence: shipped defaults -> user files ->
environment variables -> explicit overrides (later wins).
"""

from .loader import Config, ConfigLoader

__all__ = ["Config", "ConfigLoader"]
