"""Generative AI wordlists — fill the Phase-0 seam files from an LLM.

Three small modules ask the configured AI provider for TARGET-SPECIFIC candidates
and write them to the seam files the deterministic brute stages already read:

* ``ai_subwords``  -> results/<run>/ai_subwords.txt  (dns_resolve brute + permutation)
* ``ai_dirwords``  -> results/<run>/ai_dirwords.txt  (dir_bruteforce / feroxbuster)
* ``ai_params``    -> results/<run>/ai_params.txt    (param_discovery / arjun)

Each runs at the point where its best context exists (subwords early from observed
names; dirwords from crawled paths; params from fetched JS) and emits ONE schema-
constrained call, so the brute stage that follows gets AI-extrapolated candidates
ON TOP of its deterministic wordlist. The validator/resolver decides what's real,
so wrong guesses are harmless.

Format is guaranteed by the provider's JSON-schema structured-output mode (not by
prompting); the result is then sanitized (regex + dedupe + cap) before it's written.
Everything is inert when AI is off (``ctx.ai is None``) — the deterministic stages
run exactly as before. AI gates via the CLI's AI-mode stage selection.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlsplit

from ...analysis.params import mine_js_params, query_param_names
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...core.module import BaseModule
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ...prompts import PromptManager
from ..base import host_of
from .js_fetch import load_bodies

#: Shared structured-output schema — a single list of strings. The provider is
#: CONSTRAINED to this shape (Claude json_schema mode), so output is always valid.
AI_WORDS_SCHEMA = {
    "type": "object",
    "properties": {"words": {"type": "array", "items": {"type": "string"}}},
    "required": ["words"],
    "additionalProperties": False,
}

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")   # one DNS label
_PARAM_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_.-]{0,39}$")
_DIR_RE = re.compile(r"^[a-zA-Z0-9._~%/-]{1,80}$")
_CTX_CAP = 120   # cap context items fed to the model (token hygiene)


class _AiWordlist(BaseModule):
    """Shared flow for the three generative wordlist modules."""

    domain = Domain.WEB
    seam: str = ""           # output file stem (== produces sentinel)
    prompt_name: str = ""
    default_max: int = 200

    # -- overridden by subclasses -----------------------------------------
    def _context(self, ctx) -> dict:
        """Return the {{var}} payload for the prompt (+ an 'observed' list)."""
        raise NotImplementedError

    def _sanitize(self, word: str, apex: str) -> str | None:
        raise NotImplementedError

    # -- shared run --------------------------------------------------------
    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        log = get_logger(f"module.{self.name}", run_id=getattr(ctx, "run_id", None))
        spec = self._spec(ctx)
        results_dir = getattr(ctx, "results_dir", None)

        if not spec.get("enabled", True) or ctx.ai is None or results_dir is None:
            reason = ("disabled in config" if not spec.get("enabled", True)
                      else "no AI provider (ctx.ai is None — AI mode off?)" if ctx.ai is None
                      else "no results dir")
            log.info("%s: inert — %s", self.name, reason)
            result.status = ModuleStatus.SUCCESS
            result.error = reason                 # surfaced in the run summary
            result.meta = {"inert": True, "reason": reason}
            return result

        payload = self._context(ctx)
        observed = payload.pop("_observed", [])
        if not observed:
            reason = "no context yet (0 observed items to extrapolate from)"
            log.info("%s: skipped — %s", self.name, reason)
            result.status = ModuleStatus.SUCCESS
            result.error = reason                 # surfaced in the run summary
            result.meta = {"skipped": reason}
            return result

        log.info("%s: calling AI provider with %d context item(s)...", self.name, len(observed))

        max_words = int(spec.get("max_words", self.default_max) or self.default_max)
        payload["max_words"] = max_words
        apex = payload.get("apex", "")
        try:
            prompt = self._prompt(ctx).render(payload)
            resp = ctx.ai.generate(prompt, schema=AI_WORDS_SCHEMA)
        except Exception as exc:  # AIError, PromptError, network — never break the run
            log.warning("%s: AI generation failed (%s) — seam left empty", self.name, exc)
            result.status = ModuleStatus.SUCCESS
            result.error = str(exc)
            return result

        raw = (resp.parsed or {}).get("words", []) if isinstance(resp.parsed, dict) else []
        words, seen = [], set()
        for item in raw:
            w = self._sanitize(str(item), apex)
            if w and w not in seen:
                seen.add(w)
                words.append(w)
            if len(words) >= max_words:
                break

        self._write(results_dir, words)
        if ctx.repository is not None and words:
            ctx.repository.add_finding(
                ctx.run_id, kind="recon_note", severity="info",
                title=f"AI generated {len(words)} {self.seam} candidate(s)",
                detail={"seam": self.seam, "count": len(words), "sample": words[:15]},
                source=self.name,
            )
        log.info("%s: %d context item(s) -> %d AI candidate(s)", self.name, len(observed), len(words))
        result.status = ModuleStatus.SUCCESS
        result.produced = len(words)
        result.meta = {"words": len(words)}
        return result

    # -- helpers -----------------------------------------------------------
    def _write(self, results_dir, words: list[str]) -> None:
        path = Path(results_dir) / f"{self.seam}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        header = f"# {len(words)} AI-generated {self.seam} candidate(s)\n"
        path.write_text(header + "\n".join(words) + ("\n" if words else ""), encoding="utf-8")

    def _prompt(self, ctx):
        prompts_dir = (ctx.config.ai.get("prompts", {}) or {}).get("dir", "prompts")
        version = str((ctx.config.ai or {}).get("prompt_version", "v1")).strip().lower()
        name = self.prompt_name if version in ("", "v1", "default") else f"{version}/{self.prompt_name}"
        return PromptManager(prompts_dir).get("web", name)

    def _apex(self, ctx) -> str:
        for target in ctx.scope.targets:
            host = host_of(target) or target
            if host:
                return host
        return ""

    def _spec(self, ctx) -> dict:
        return (ctx.config.pipeline.get(self.name, {}) or {})


@register
class AiSubwords(_AiWordlist):
    name = "ai_subwords"
    stage = Stage.DISCOVERY
    # require asset_discovery's unique marker (NOT "subdomain" — that's also produced
    # by dns_resolve, which requires us back => cycle). This orders us after passive
    # enumeration but before dns_resolve.
    requires = ("passive_subdomains",)
    produces = ("ai_subwords",)
    seam = "ai_subwords"
    prompt_name = "ai_subwords"

    def _context(self, ctx) -> dict:
        apex = self._apex(ctx)
        labels, seen = [], set()
        if ctx.repository is not None:
            for asset in ctx.repository.list_assets(ctx.run_id, "subdomain"):
                key = asset["canonical_key"]
                label = key[: -len(apex) - 1] if apex and key.endswith("." + apex) else key
                label = label.strip().lower()
                if label and label not in seen:
                    seen.add(label)
                    labels.append(label)
        labels = labels[:_CTX_CAP]
        return {"apex": apex, "known_subs": "\n".join(labels) or "(none)", "_observed": labels}

    def _sanitize(self, word, apex):
        w = word.strip().lower().lstrip(".")
        if apex and w.endswith("." + apex):       # model returned a full FQDN -> keep the label
            w = w[: -len(apex) - 1]
        w = w.split(".")[0]                        # labels only (no dots)
        return w if _LABEL_RE.match(w) else None


@register
class AiDirwords(_AiWordlist):
    name = "ai_dirwords"
    stage = Stage.COLLECTION
    # require "endpoint" (crawling-only) NOT "url" (dir_bruteforce produces url => cycle).
    requires = ("endpoint",)
    produces = ("ai_dirwords",)
    seam = "ai_dirwords"
    prompt_name = "ai_dirwords"

    def _context(self, ctx) -> dict:
        paths, seen = [], set()
        tech = []
        if ctx.repository is not None:
            for asset in ctx.repository.list_assets(ctx.run_id, "url"):
                p = urlsplit(asset["canonical_key"]).path.strip("/")
                if p and p not in seen:
                    seen.add(p)
                    paths.append(p)
            tech = [a["canonical_key"] for a in ctx.repository.list_assets(ctx.run_id, "technology")]
        paths = paths[:_CTX_CAP]
        return {"apex": self._apex(ctx), "known_paths": "\n".join(paths) or "(none)",
                "tech": ", ".join(tech[:30]) or "(unknown)", "_observed": paths}

    def _sanitize(self, word, apex):
        w = word.strip().strip("/")
        return w if w and _DIR_RE.match(w) and ".." not in w else None


@register
class AiParams(_AiWordlist):
    name = "ai_params"
    stage = Stage.COLLECTION
    requires = ("response",)
    produces = ("ai_params",)
    seam = "ai_params"
    prompt_name = "ai_params"
    default_max = 150

    def _context(self, ctx) -> dict:
        params, tech = set(), []
        if ctx.repository is not None:
            for asset in ctx.repository.list_assets(ctx.run_id, "url"):
                params |= query_param_names(asset["canonical_key"])
            tech = [a["canonical_key"] for a in ctx.repository.list_assets(ctx.run_id, "technology")]
        for _url, body in load_bodies(getattr(ctx, "results_dir", None)):
            params |= mine_js_params(body)
        observed = sorted(params)[:_CTX_CAP]
        return {"apex": self._apex(ctx), "known_params": "\n".join(observed) or "(none)",
                "tech": ", ".join(tech[:30]) or "(unknown)", "_observed": observed}

    def _sanitize(self, word, apex):
        w = word.strip()
        return w if _PARAM_RE.match(w) else None
