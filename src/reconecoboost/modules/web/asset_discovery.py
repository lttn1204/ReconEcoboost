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
    # "passive_subdomains" is a marker (only this module produces it) so ai_subwords
    # can order itself after passive enum but before dns_resolve without a cycle.
    produces = ("subdomain", "passive_subdomains")
    tool = "subfinder"
    parser = "subfinder"
    input_type = None  # seeded from scope targets
    # NOT recursive: subfinder is PASSIVE and already enumerates deeply, so re-running
    # it on every discovered subdomain yields almost nothing new while multiplying runs
    # explosively (depth 3 on a big org = dozens-to-hundreds of subfinder runs that can
    # hang the pipeline before anything is validated). Recursive sub-of-sub discovery is
    # left to ACTIVE brute (dns_resolve, gated + capped) and the bounded discovery loop.
    recursive = False

    def command(self, tool, item, ctx) -> ToolInvocation:
        return ToolInvocation(tool.argv("-silent", "-d", item))

    def extra_records(self, ctx) -> list:
        # Seed the explicit target(s) as subdomains so the apex itself is probed
        # downstream — subfinder only returns subdomains, not the seed apex.
        return [
            ParsedRecord("subdomain", host_of(target) or target, tool="seed")
            for target in ctx.scope.targets
        ]
