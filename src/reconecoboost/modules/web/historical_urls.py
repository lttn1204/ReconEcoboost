"""Historical URL collection with gau.

gau has no result-count cap, so on a very large domain it can return a lot. We
keep it host-scoped (no ``--subs`` by default) and blacklist static-asset
extensions (images/fonts/media/css) — they're noise for param/secret analysis and
trimming them cuts the archive volume meaningfully. Tune under ``historical_urls``.
"""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of

_DEFAULT_BLACKLIST = ["png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "woff",
                      "woff2", "ttf", "eot", "otf", "css", "mp4", "mp3", "avi",
                      "mov", "webm", "wasm"]


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
        spec = (ctx.config.pipeline.get("historical_urls", {}) or {})
        args: list[str] = []
        blacklist = spec.get("blacklist", _DEFAULT_BLACKLIST)
        if blacklist:
            args += ["--blacklist", ",".join(str(b).lstrip(".") for b in blacklist)]
        if spec.get("subs"):
            args.append("--subs")          # off by default — stay on the exact host
        if spec.get("from"):
            args += ["--from", str(spec["from"])]
        if spec.get("to"):
            args += ["--to", str(spec["to"])]
        # gau takes a bare domain/host, not a full origin URL.
        args.append(host_of(item) or item)
        return ToolInvocation(tool.argv(*args))
