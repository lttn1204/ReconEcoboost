"""Asset discovery — subdomain enumeration with subfinder."""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...engine import ParsedRecord
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of


@register
class AssetDiscovery(ToolModule):
    name = "asset_discovery"
    domain = Domain.WEB
    stage = Stage.DISCOVERY
    requires = ()
    produces = ("subdomain",)
    tool = "subfinder"
    parser = "subfinder"
    input_type = None  # seeded from scope targets
    recursive = True   # re-feed found subdomains as seeds (depth from config)

    def command(self, tool, item, ctx) -> ToolInvocation:
        return ToolInvocation(tool.argv("-silent", "-d", item))

    def extra_records(self, ctx) -> list:
        # Seed the explicit target(s) as subdomains so the apex itself is probed
        # downstream — subfinder only returns subdomains, not the seed apex.
        return [
            ParsedRecord("subdomain", host_of(target) or target, tool="seed")
            for target in ctx.scope.targets
        ]
