"""Discover subdomains referenced in fetched page content (separate + toggleable).

Reads the bodies ``js_fetch`` cached (HTML/JS/JSON/CSP) and regex-extracts
in-scope subdomains of the target apex, persisting them as ``subdomain`` assets —
catching hosts that DNS/vhost brute and passive enum miss (only *mentioned* in a
page). Fully independent of ``js_intel`` / ``secret_scan`` (its own ``enabled``
toggle): turning it off doesn't touch them, and vice versa. No LLM, zero tokens.

Declares ``produces=("content_subdomain",)`` (a sentinel) — it persists
``subdomain`` assets directly but does NOT declare producing ``subdomain``, to
avoid a DAG cycle with dns_resolve. Re-fuzzing these is the future
discovery-loop's job; for now they're recorded for the report/AI and re-runs.
"""

from __future__ import annotations

from pathlib import Path

from ...analysis.content_subdomains import extract_subdomains
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...core.module import BaseModule
from ...engine import Normalizer, ParsedRecord
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ..base import host_of
from .js_fetch import load_bodies


@register
class ContentSubdomains(BaseModule):
    name = "content_subdomains"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("response",)
    produces = ("content_subdomain",)   # persists `subdomain` directly; sentinel avoids DAG cycle
    tool = None
    parser = None

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        if not self._spec(ctx).get("enabled", True):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"disabled": True}
            return result
        if ctx.repository is None:
            raise NotImplementedError("persistence not available on context")

        bodies = load_bodies(getattr(ctx, "results_dir", None))
        if not bodies:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"bodies": 0}
            return result

        apexes = [host_of(t) or t for t in ctx.scope.targets]
        found: set[str] = set()
        for _url, body in bodies:
            found |= extract_subdomains(body, apexes)

        # scope-gated: only in-scope subdomains (wildcard scope) are kept
        records = [
            ParsedRecord("subdomain", sub, attributes={"source": "content"}, tool="content_subdomains")
            for sub in sorted(found) if ctx.scope.is_allowed(sub)
        ]
        produced = 0
        if records:
            produced = ctx.repository.persist_normalization(
                ctx.run_id, Normalizer().normalize(records))["assets"]

        self._write_results(ctx, [r.key for r in records])
        get_logger("module.content_subdomains", run_id=ctx.run_id).info(
            "content_subdomains: %d body(ies), %d in-scope subdomain(s) from page content",
            len(bodies), len(records),
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = produced
        result.meta = {"bodies": len(bodies), "subdomains": len(records)}
        return result

    def _write_results(self, ctx, subs: list[str]) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        path = Path(results_dir) / "content_subdomains.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {len(subs)} subdomain(s) found in page content\n"
                        + "\n".join(sorted(subs)) + ("\n" if subs else ""), encoding="utf-8")

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("content_subdomains", {}) or {})
