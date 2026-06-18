"""Tests for the Claude Code (subscription) provider — no live CLI calls."""

import json

import pytest

from reconecoboost.ai import ClaudeCodeProvider, build_provider
from reconecoboost.core.errors import AIError

SCHEMA = {
    "type": "object",
    "properties": {"summary": {"type": "string"}},
    "required": ["summary"],
    "additionalProperties": False,
}


def _envelope(result_text, is_error=False):
    return json.dumps({
        "type": "result", "subtype": "success", "is_error": is_error,
        "result": result_text, "total_cost_usd": 0.0, "usage": {},
    })


def test_builds_headless_argv_and_feeds_prompt_via_stdin():
    captured = {}

    def runner(argv, input_text):
        captured["argv"] = argv
        captured["stdin"] = input_text
        return _envelope(json.dumps({"summary": "ok"})), 0

    provider = ClaudeCodeProvider(model="sonnet", runner=runner)
    resp = provider.generate("analyze this graph", schema=SCHEMA)

    argv = captured["argv"]
    assert argv[0] == "claude"
    assert "-p" in argv and "--output-format" in argv and "json" in argv
    assert argv[argv.index("--model") + 1] == "sonnet"
    # prompt (with the schema instruction appended) is sent on stdin
    assert "analyze this graph" in captured["stdin"]
    assert "JSON Schema" in captured["stdin"]
    # structured result parsed out of the CLI's JSON envelope
    assert resp.parsed == {"summary": "ok"}


def test_strips_markdown_fences_from_result():
    fenced = "```json\n{\"summary\": \"fenced\"}\n```"
    provider = ClaudeCodeProvider(runner=lambda a, i: (_envelope(fenced), 0))
    assert provider.generate("x", schema=SCHEMA).parsed == {"summary": "fenced"}


def test_nonzero_exit_raises():
    provider = ClaudeCodeProvider(runner=lambda a, i: ("boom", 1))
    with pytest.raises(AIError):
        provider.generate("x", schema=SCHEMA)


def test_cli_is_error_raises():
    provider = ClaudeCodeProvider(runner=lambda a, i: (_envelope("nope", is_error=True), 0))
    with pytest.raises(AIError):
        provider.generate("x", schema=SCHEMA)


def test_non_json_result_for_schema_raises():
    provider = ClaudeCodeProvider(runner=lambda a, i: (_envelope("not json at all"), 0))
    with pytest.raises(AIError):
        provider.generate("x", schema=SCHEMA)


def test_factory_builds_claude_code():
    provider = build_provider({"provider": "claude-code", "model": "opus"})
    assert isinstance(provider, ClaudeCodeProvider)
    assert provider.model == "opus"
