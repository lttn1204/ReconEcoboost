"""Tests for the AI provider abstraction, stub, and factory."""

import pytest

from reconecoboost.ai import ClaudeProvider, StubProvider, build_provider
from reconecoboost.ai.stub import _stub_from_schema
from reconecoboost.core.errors import AIError

SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "items": {"type": "array", "items": {"type": "string"}},
        "count": {"type": "integer"},
    },
    "required": ["summary", "items", "count"],
    "additionalProperties": False,
}


def test_stub_from_schema_shapes():
    stub = _stub_from_schema(SCHEMA)
    assert stub == {"summary": "", "items": [], "count": 0}


def test_stub_provider_derives_from_schema():
    resp = StubProvider().generate("anything", schema=SCHEMA)
    assert resp.parsed == {"summary": "", "items": [], "count": 0}
    assert resp.model == "stub"


def test_stub_provider_returns_canned_payload():
    canned = {"summary": "hi", "items": ["a"], "count": 1}
    resp = StubProvider(parsed=canned).generate("x", schema=SCHEMA)
    assert resp.parsed == canned


def test_stub_provider_no_schema_is_text():
    resp = StubProvider().generate("x")
    assert resp.parsed is None
    assert resp.text


def test_factory_builds_claude_by_default():
    provider = build_provider({"provider": "claude", "model": "claude-opus-4-8"})
    assert isinstance(provider, ClaudeProvider)
    assert provider.model == "claude-opus-4-8"


def test_factory_builds_stub():
    assert isinstance(build_provider({"provider": "stub"}), StubProvider)


def test_factory_future_provider_raises():
    with pytest.raises(AIError):
        build_provider({"provider": "openai"})


def test_factory_unknown_provider_raises():
    with pytest.raises(AIError):
        build_provider({"provider": "nonsense"})
