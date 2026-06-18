"""Alive detection — HTTP probing of subdomains with httpx."""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of


@register
class AliveDetection(ToolModule):
    name = "alive_detection"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("subdomain",)
    produces = ("host",)
    tool = "httpx"
    parser = "httpx"
    input_type = "subdomain"
    batch = True  # feed all subdomains via stdin in one invocation
    output_ext = "jsonl"

    def _gather_inputs(self, ctx) -> list[str]:
        # Probe discovered subdomains AND the explicit seed targets — so the
        # targets are reached even when discovery is skipped (e.g. 'direct'
        # profile) or didn't surface them. Deduped, order preserved.
        discovered = super()._gather_inputs(ctx)
        seeds = [host_of(t) or t for t in ctx.scope.targets]
        seen: set[str] = set()
        out: list[str] = []
        for host in list(discovered) + seeds:
            if host and host not in seen:
                seen.add(host)
                out.append(host)
        return out

    def batch_command(self, tool, items, ctx) -> ToolInvocation:
        return ToolInvocation(tool.argv("-silent", "-json"), input_text="\n".join(items))
