"""Alive detection — HTTP probing of subdomains with httpx."""

from __future__ import annotations

import json

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of
from .dns_resolve import host_reachable, network_preference


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
        # Which hosts are probed is governed solely by dns_resolve.prefer:
        # public=skip internal-only hosts, internal/both=probe everything.
        # Seeds are always probed.
        prefer = network_preference(ctx)
        discovered: list[str] = []
        for asset in ctx.repository.list_assets(ctx.run_id, "subdomain"):
            try:
                attrs = json.loads(asset.get("attributes_json") or "{}")
            except (json.JSONDecodeError, TypeError):
                attrs = {}
            if not host_reachable(attrs, prefer):
                continue
            discovered.append(asset["canonical_key"])

        seeds = [host_of(t) or t for t in ctx.scope.targets]
        seen: set[str] = set()
        out: list[str] = []
        for host in discovered + seeds:
            if host and host not in seen:
                seen.add(host)
                out.append(host)
        return out

    def batch_command(self, tool, items, ctx) -> ToolInvocation:
        spec = (ctx.config.pipeline.get("alive_detection", {}) or {})
        timeout = int(spec.get("timeout_s", 10))
        return ToolInvocation(tool.argv("-silent", "-json", "-t", str(timeout)),
                              input_text="\n".join(items))
