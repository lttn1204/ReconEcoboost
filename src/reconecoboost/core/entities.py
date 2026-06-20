"""Canonical entity vocabulary (in-memory form).

These are the deduplicated, schema-stable records the Normalizer emits and the
persistence layer will later store as ``asset`` / ``provenance`` / ``relation``
rows (architecture doc 09). They live in ``core`` because they are the shared
taxonomy that engine, persistence, and graph all speak — none of them owns it.

No database concerns here: these are plain dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit


@dataclass
class Provenance:
    """Which tool/module produced or confirmed a fact, and how confidently."""

    tool: str
    module: str | None = None
    confidence: float = 1.0
    raw_ref: str | None = None  # path to the raw capture, never the blob itself


@dataclass
class CanonicalEntity:
    """A deduplicated node in the asset graph.

    Identity is ``(asset_type, canonical_key)``. ``attributes`` holds the merged
    domain detail; ``sources`` accumulates provenance from every tool that saw it.
    """

    asset_type: str
    canonical_key: str
    attributes: dict[str, Any] = field(default_factory=dict)
    sources: list[Provenance] = field(default_factory=list)

    @property
    def identity(self) -> tuple[str, str]:
        return (self.asset_type, self.canonical_key)


@dataclass
class Relation:
    """A typed, directed edge between two entities (the graph's storage form)."""

    src_type: str
    src_key: str
    rel_type: str
    dst_type: str
    dst_key: str
    confidence: float = 1.0
    source: str | None = None  # "rule" | "ai" | tool name

    @property
    def identity(self) -> tuple[str, str, str, str, str]:
        return (self.src_type, self.src_key, self.rel_type, self.dst_type, self.dst_key)


def canonical_key(asset_type: str, key: str) -> str:
    """Normalize a natural key so equal facts collapse to one identity.

    Lives in ``core`` because it is part of the shared taxonomy — the engine
    Normalizer and the persistence layer must agree on what "the same entity"
    means.
    """
    value = key.strip()
    if asset_type in ("subdomain", "host"):
        return value.lower().rstrip(".")
    if asset_type == "technology":
        return value.lower()
    if asset_type in ("url", "endpoint"):
        # Scheme + host are case-insensitive → lowercase them so
        # `https://Google.Com/x` and `https://google.com/x` collapse. The path,
        # query and fragment ARE case-sensitive, so they are preserved as-is.
        parts = urlsplit(value)
        if parts.scheme and parts.netloc:
            netloc = parts.netloc.lower().rstrip(".")
            return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment))
        return value
    # artifact / others: keep as-is.
    return value
