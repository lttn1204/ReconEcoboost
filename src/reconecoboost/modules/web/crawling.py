"""Crawling — active crawl of live hosts with katana.

Bounded by default: katana otherwise crawls a host **unlimited** (no page or time
cap), so crawling a huge site (e.g. a Google property) streams gigabytes that the
executor buffers in memory → OOM. ``max_domain_pages`` + ``crawl_duration`` cap the
volume; tune them in ``pipeline.yaml`` under ``crawling``.
"""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule


@register
class Crawling(ToolModule):
    name = "crawling"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("host",)
    produces = ("url", "endpoint")
    tool = "katana"
    parser = "katana"
    input_type = "host"
    output_ext = "jsonl"

    def command(self, tool, item, ctx) -> ToolInvocation:
        spec = (ctx.config.pipeline.get("crawling", {}) or {})
        args = ["-silent", "-jsonl", "-u", item]

        depth = spec.get("depth", 3)
        if depth:
            args += ["-d", str(int(depth))]
        # The key OOM guard: cap pages per domain (katana default is UNLIMITED).
        max_pages = spec.get("max_domain_pages", 2000)
        if max_pages:
            args += ["-mdp", str(int(max_pages))]
        # Hard time cap so a fast/huge site can't run away.
        duration = spec.get("crawl_duration", "5m")
        if duration:
            args += ["-ct", str(duration)]
        scope = spec.get("field_scope")          # dn | rdn | fqdn (katana default rdn)
        if scope:
            args += ["-fs", str(scope)]
        if spec.get("js_crawl"):
            args.append("-jc")

        return ToolInvocation(tool.argv(*args))
