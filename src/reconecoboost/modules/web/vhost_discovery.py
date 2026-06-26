"""Virtual-host discovery with ffuf — fuzz Host over the dnsx IP inventory.

Finds **DNS-less vhosts**: sites served on an IP via the ``Host:`` header with no
public DNS record (staging/admin/origin sites). dnsx can't see these (nothing to
resolve), so we fuzz ``Host: FUZZ.<apex>`` against:

* every reachable IP that dnsx discovered (deduped, internal IPs skipped, capped
  by ``max_ips``), and
* the apex domain itself (so it still works when dnsx didn't run).

A match means the server already answered for that Host, so the vhost is **live**
— we register it directly as a ``host`` (no second probe, and producing ``host``
instead of ``subdomain`` avoids a DAG cycle with dns_resolve). Runs only when the
scope enumerates (it's an ENUMERATION stage, gated on a wildcard scope).
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from ...core.models import Domain, Stage
from ...engine import ParsedRecord
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of
from .dns_resolve import family_ips, network_preference

_DEFAULT_WORDLIST = "wordlists/ffuf/vhosts.txt"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@register
class VhostDiscovery(ToolModule):
    name = "vhost_discovery"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("subdomain",)   # after asset_discovery + dns_resolve (needs IPs)
    produces = ("host",)        # matched vhosts are already live -> host (no cycle)
    tool = "ffuf"
    parser = "ffuf_vhost"
    input_type = None           # frontier built from IP inventory, not the store directly
    output_ext = "txt"
    recursive = False

    # -- frontier: scheme|target|apex combos --------------------------------

    def _gather_inputs(self, ctx) -> list[str]:
        if not self._spec(ctx).get("enabled", True):
            return []
        apexes: list[str] = []
        for target in ctx.scope.targets:
            host = host_of(target) or target
            if host and host not in apexes:
                apexes.append(host)

        # Pick which IP family to fuzz from the network preference: public-only
        # (default), internal-only, or both. From outside, internal IPs aren't
        # routable, so the default drops them; set dns_resolve.prefer to include
        # them when running from inside the network.
        prefer = network_preference(ctx)
        ips, seen = [], set()
        if ctx.repository is not None:
            for asset in ctx.repository.list_assets(ctx.run_id, "subdomain"):
                try:
                    attrs = json.loads(asset.get("attributes_json") or "{}")
                except (json.JSONDecodeError, TypeError):
                    attrs = {}
                for ip in family_ips(attrs.get("ip", []), prefer):
                    if ip not in seen:
                        seen.add(ip)
                        ips.append(ip)
        cap = int(self._spec(ctx).get("max_ips", 50) or 0)
        if cap:
            ips = ips[:cap]

        schemes = self._spec(ctx).get("schemes", ["https", "http"])
        combos: list[str] = []
        for apex in apexes:
            for target in [*ips, apex]:   # IP-based + name-based (no regression)
                for scheme in schemes:
                    combos.append(f"{scheme}|{target}|{apex}")
        return combos

    def command(self, tool, item, ctx) -> ToolInvocation:
        scheme, target, apex = item.split("|", 2)
        # -timeout bounds per-request waits: a filtered/closed port (e.g. http on a
        # CDN edge IP) otherwise hangs ffuf's calibration ~10s/req → ~40s per run.
        req_timeout = int(self._spec(ctx).get("request_timeout_s", 7))
        args = [
            "-w", self._wordlist(ctx),
            "-u", f"{scheme}://{target}/",
            "-H", f"Host: FUZZ.{apex}",
            "-timeout", str(req_timeout),
            "-ic", "-of", "json", "-o", "/dev/stdout", "-s",
        ]
        if self._spec(ctx).get("auto_calibrate", True):
            args.append("-ac")   # drop the catch-all baseline -> fewer false positives
        return ToolInvocation(tool.argv(*args))

    def refine_records(self, ctx, item, records: list) -> list:
        """Turn matched FUZZ keywords into live `host` records (origin)."""
        scheme, target, apex = item.split("|", 2)
        out = []
        for record in records:
            host_key = f"{scheme}://{record.key}.{apex}"
            attrs = {"vhost": True}
            if record.attributes.get("status") is not None:
                attrs["status_code"] = record.attributes["status"]
            if record.attributes.get("length") is not None:
                attrs["content_length"] = record.attributes["length"]
            if _is_ip(target):
                attrs["vhost_ip"] = target
            out.append(ParsedRecord("host", host_key, attributes=attrs, tool="ffuf_vhost"))
        return out

    def format_capture(self, raw_stdout: str) -> str:
        return ""  # no per-invocation files; consolidated summary in after_persist

    def after_persist(self, ctx, entities) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        rows = []
        for e in entities:
            attrs = e.attributes or {}
            if e.asset_type != "host" or not attrs.get("vhost"):
                continue
            rows.append(f"{e.canonical_key}\tip={attrs.get('vhost_ip', 'name')}"
                        f"\tstatus={attrs.get('status_code', '?')}\tsize={attrs.get('content_length', '?')}")
        path = Path(results_dir) / "vhost.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {len(rows)} vhost(s) (DNS-less hosts found via Host fuzzing)\n"
                        + "\n".join(sorted(rows)) + ("\n" if rows else ""), encoding="utf-8")

    # -- config -------------------------------------------------------------

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("vhost_discovery", {}) or {})

    @staticmethod
    def _wordlist(ctx) -> str:
        entry = (ctx.config.wordlists.get("wordlists", {}) or {}).get("vhosts") or {}
        return entry.get("path", _DEFAULT_WORDLIST)
