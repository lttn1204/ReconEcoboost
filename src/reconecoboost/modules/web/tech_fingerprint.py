"""Technology fingerprinting with whatweb."""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule


@register
class TechFingerprint(ToolModule):
    name = "tech_fingerprint"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("host",)
    produces = ("technology",)
    tool = "whatweb"
    parser = "whatweb"
    input_type = "host"
    output_ext = "json"

    def command(self, tool, item, ctx) -> ToolInvocation:
        return ToolInvocation(tool.argv("--log-json=/dev/stdout", "--no-errors", item))
