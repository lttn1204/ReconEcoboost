"""Historical URL collection with gau."""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of


@register
class HistoricalUrls(ToolModule):
    name = "historical_urls"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("host",)
    produces = ("url",)
    tool = "gau"
    parser = "gau"
    input_type = "host"

    def command(self, tool, item, ctx) -> ToolInvocation:
        # gau takes a bare domain/host, not a full origin URL.
        return ToolInvocation(tool.argv(host_of(item) or item))
