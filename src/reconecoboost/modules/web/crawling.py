"""Crawling — active crawl of live hosts with katana."""

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
        return ToolInvocation(tool.argv("-silent", "-jsonl", "-u", item))
