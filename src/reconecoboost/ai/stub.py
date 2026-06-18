"""Stub provider — deterministic, offline, no network.

Used for tests and offline runs (engagements where recon data must not leave the
host). When a schema is supplied it returns a minimal object that satisfies the
schema's shape; callers can also inject a canned ``parsed`` payload.
"""

from __future__ import annotations

import json
from typing import Any

from .base import AIProvider, AIResponse


def _stub_from_schema(schema: dict[str, Any]) -> Any:
    kind = schema.get("type")
    if kind == "object":
        props = schema.get("properties", {})
        required = schema.get("required", list(props.keys()))
        return {key: _stub_from_schema(props[key]) for key in required if key in props}
    if kind == "array":
        return []
    if kind in ("integer", "number"):
        return 0
    if kind == "boolean":
        return False
    return ""  # string / unspecified


class StubProvider(AIProvider):
    def __init__(self, parsed: dict[str, Any] | None = None) -> None:
        self._parsed = parsed  # explicit canned response, or None to derive from schema

    def generate(
        self,
        prompt: str,
        *,
        schema: dict[str, Any] | None = None,
        system: str | None = None,
        max_tokens: int | None = None,
        effort: str | None = None,
    ) -> AIResponse:
        if schema is None:
            return AIResponse(text="(stub response)", parsed=None, model="stub")
        parsed = self._parsed if self._parsed is not None else _stub_from_schema(schema)
        return AIResponse(text=json.dumps(parsed), parsed=parsed, model="stub")
