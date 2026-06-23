"""Probe discovered URLs with httpx to record liveness/status.

Crawled (katana) and historical (gau) URLs are never validated — many are dead.
This stage runs httpx over the discovered URLs and records each one's
``status_code`` (and size/title/tech) onto its URL asset. Downstream, nuclei
scans only URLs confirmed live, instead of every unvalidated archive URL.

Runs after the URL-producing collection stages (requires "url") and re-emits
URL records (produces "url"), so it lands before normalization and nuclei.
"""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule


@register
class UrlProbe(ToolModule):
    name = "url_probe"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("url",)
    produces = ("url",)
    tool = "httpx"
    parser = "httpx_url"
    input_type = "url"
    batch = True  # feed all URLs to one httpx invocation via stdin
    output_ext = "jsonl"

    def batch_command(self, tool, items, ctx) -> ToolInvocation:
        spec = (ctx.config.pipeline.get("url_probe", {}) or {})
        timeout = int(spec.get("timeout_s", 15))
        return ToolInvocation(tool.argv("-silent", "-json", "-t", str(timeout)),
                              input_text="\n".join(items))
