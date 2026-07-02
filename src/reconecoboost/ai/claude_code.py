"""Claude Code provider — drive the AI stage via the `claude` CLI (subscription).

Instead of the metered Messages API, this runs Claude Code headless
(`claude -p --output-format json`), which authenticates with your Pro/Max
subscription. The prompt is fed on stdin; structured output is requested by
appending the JSON schema to the prompt (Claude Code has no API-level schema
enforcement) and parsing the returned JSON.

Subscription vs API: Claude Code uses your OAuth/subscription login UNLESS
``ANTHROPIC_API_KEY`` is set (then it bills the API). To guarantee subscription
billing, this adapter runs the CLI with ``ANTHROPIC_API_KEY`` removed from the
environment. You must be logged in (`claude` → /login) first.

Note: automated use of a consumer subscription is subject to Anthropic's usage
policy and your plan's rate limits.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Callable

from ..core.errors import AIError
from .base import AIProvider, AIResponse

DEFAULT_MODEL = "sonnet"
DEFAULT_TIMEOUT_S = 300
# Keep the analysis pure: don't let Claude Code touch the filesystem / web / shell.
_DISALLOWED_TOOLS = "Bash Edit Write Read NotebookEdit WebFetch WebSearch Glob Grep Task"


def _extract_json(text: str) -> dict | None:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = re.sub(r"^json\s*", "", t, flags=re.IGNORECASE)
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        parsed = json.loads(t[start:end + 1])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


class ClaudeCodeProvider(AIProvider):
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        cli: str = "claude",
        timeout_s: int = DEFAULT_TIMEOUT_S,
        use_subscription: bool = True,
        runner: Callable[[list[str], str], tuple[str, int]] | None = None,
    ) -> None:
        self.model = model
        self.cli = cli
        self.timeout_s = timeout_s
        self.use_subscription = use_subscription
        self._runner = runner or self._run_cli

    def _run_cli(self, argv: list[str], input_text: str) -> tuple[str, int]:
        env = dict(os.environ)
        if self.use_subscription:
            # Force the subscription/OAuth login rather than API-key billing.
            env.pop("ANTHROPIC_API_KEY", None)
        try:
            proc = subprocess.run(
                argv, input=input_text, capture_output=True, text=True,
                encoding="utf-8", errors="replace",  # CLI emits UTF-8; don't use the
                timeout=self.timeout_s, env=env,      # machine locale (mangles —/quotes)
            )
        except FileNotFoundError as exc:
            raise AIError(f"Claude Code CLI '{self.cli}' not found on PATH.") from exc
        except subprocess.TimeoutExpired as exc:
            raise AIError(f"Claude Code timed out after {self.timeout_s}s.") from exc
        return proc.stdout, proc.returncode

    def generate(
        self,
        prompt: str,
        *,
        schema: dict[str, Any] | None = None,
        system: str | None = None,
        max_tokens: int | None = None,
        effort: str | None = None,
    ) -> AIResponse:
        full_prompt = prompt
        if schema is not None:
            full_prompt += (
                "\n\nReturn ONLY a single JSON object that matches this JSON Schema. "
                "No prose, no explanation, no markdown code fences:\n"
                + json.dumps(schema)
            )

        argv = [
            self.cli, "-p",
            "--output-format", "json",
            "--model", self.model,
            "--no-session-persistence",
            "--disallowed-tools", _DISALLOWED_TOOLS,
        ]
        if system:
            argv += ["--system-prompt", system]

        stdout, code = self._runner(argv, full_prompt)
        if code != 0:
            raise AIError(f"Claude Code exited with code {code}: {stdout[:300]}")

        try:
            envelope = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise AIError(f"Claude Code returned non-JSON output: {exc}") from exc
        if envelope.get("is_error"):
            raise AIError(f"Claude Code reported an error: {envelope.get('result') or envelope}")

        text = envelope.get("result", "") or ""
        parsed = None
        if schema is not None:
            parsed = _extract_json(text)
            if parsed is None:
                raise AIError("Claude Code response was not valid JSON for the requested schema.")

        usage = {
            "cost_usd": envelope.get("total_cost_usd"),
            "usage": envelope.get("usage"),
        }
        return AIResponse(text=text, parsed=parsed, model=self.model, usage=usage)

    def capabilities(self) -> dict[str, Any]:
        return {"structured_output": True, "streaming": False, "backend": "claude-code"}
