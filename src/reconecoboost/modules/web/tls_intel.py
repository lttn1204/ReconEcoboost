"""TLS cert intelligence (tlsx) — mine subdomains from certificate SAN/CN.

A TLS certificate usually lists every hostname it's valid for in its Subject
Alternative Names. Pulling SANs off the certs of already-known hosts surfaces
sibling subdomains that passive sources and DNS brute-force miss (e.g. an IP whose
cert covers ``*.lpbank.com.vn`` + several explicit hosts). Passive-ish: one TLS
handshake per known host, no fuzzing.

Persists ``subdomain`` assets directly but declares the ``tls`` sentinel to avoid a
DAG cycle with dns_resolve (same trick as permutation/content_subdomains). New names
are resolved/crawled only when ``discovery.loop`` is enabled. Out-of-scope SANs
(other domains a shared cert covers) are dropped by the scope filter.
Saved to results/<run_id>/tls_intel.txt.
"""

from __future__ import annotations

from pathlib import Path

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule


@register
class TlsIntel(ToolModule):
    name = "tls_intel"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("subdomain",)
    produces = ("tls",)          # persists `subdomain` directly; sentinel avoids DAG cycle
    tool = "tlsx"
    parser = "tlsx"
    input_type = "subdomain"
    batch = True                 # feed all known hosts to one tlsx run via stdin
    output_ext = "jsonl"

    def _gather_inputs(self, ctx) -> list[str]:
        if not self._spec(ctx).get("enabled", True):
            return []
        return super()._gather_inputs(ctx)

    def batch_command(self, tool, items, ctx) -> ToolInvocation:
        return ToolInvocation(tool.argv("-san", "-cn", "-json", "-silent"),
                              input_text="\n".join(items))

    def after_persist(self, ctx, entities) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        names = sorted({e.canonical_key for e in entities if e.asset_type == "subdomain"})
        path = Path(results_dir) / "tls_intel.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {len(names)} subdomain(s) from TLS cert SAN/CN\n"
                        + "\n".join(names) + ("\n" if names else ""), encoding="utf-8")

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("tls_intel", {}) or {})
