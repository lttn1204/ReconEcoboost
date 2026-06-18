"""Prompt Manager — loads external Markdown templates and renders them.

Prompts live outside Python under ``prompts/<domain>/<task>.md`` (architecture
doc 12), each with optional YAML front-matter (version, model, expected schema)
and a body. Rendering is a minimal ``{{ var }}`` substitution — deliberately not
a full template engine, since prompt bodies contain JSON braces we must not
touch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.errors import PromptError

_VAR = re.compile(r"{{\s*(\w+)\s*}}")
_FRONT_MATTER = re.compile(r"^---\n(.*?)\n---\n?(.*)$", re.DOTALL)


@dataclass
class Prompt:
    """A loaded prompt template: parsed front-matter + raw body."""

    name: str
    body: str
    meta: dict[str, Any] = field(default_factory=dict)

    def render(self, context: dict[str, Any]) -> str:
        def replace(match: re.Match) -> str:
            key = match.group(1)
            if key not in context:
                raise PromptError(f"Prompt '{self.name}' references unknown variable '{key}'")
            return str(context[key])

        return _VAR.sub(replace, self.body)


class PromptManager:
    """Loads and renders prompt templates from a directory tree."""

    def __init__(self, prompts_dir: str | Path) -> None:
        self.prompts_dir = Path(prompts_dir)
        self._cache: dict[tuple[str, str], Prompt] = {}

    def get(self, domain: str, name: str) -> Prompt:
        key = (domain, name)
        if key in self._cache:
            return self._cache[key]

        path = self.prompts_dir / domain / f"{name}.md"
        if not path.exists():
            raise PromptError(f"Prompt not found: {path}")

        raw = path.read_text(encoding="utf-8")
        meta, body = self._split_front_matter(raw)
        prompt = Prompt(name=f"{domain}/{name}", body=body, meta=meta)
        self._cache[key] = prompt
        return prompt

    def render(self, domain: str, name: str, context: dict[str, Any]) -> str:
        return self.get(domain, name).render(context)

    @staticmethod
    def _split_front_matter(raw: str) -> tuple[dict[str, Any], str]:
        match = _FRONT_MATTER.match(raw)
        if not match:
            return {}, raw.strip()
        front, body = match.group(1), match.group(2)
        try:
            import yaml
            meta = yaml.safe_load(front) or {}
        except Exception:  # front-matter is metadata; never fatal to rendering
            meta = {}
        if not isinstance(meta, dict):
            meta = {}
        return meta, body.strip()
