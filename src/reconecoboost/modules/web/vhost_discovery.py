"""Virtual-host discovery with ffuf (Host-header fuzzing).

A sibling of asset_discovery in the DISCOVERY stage: instead of passive
enumeration, it fuzzes the ``Host:`` header against the target to find virtual
hosts served from the same address. Discovered vhosts are emitted as
``subdomain`` entities, so they flow into the rest of the pipeline exactly like
subfinder results.

Example of "easy to add a tool": this is a self-contained module + a parser,
with no changes to the engine, pipeline, graph, or storage.
"""

from __future__ import annotations

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of
from .parsers import extract_ffuf_json

_DEFAULT_WORDLIST = "wordlists/ffuf/vhosts.txt"


@register
class VhostDiscovery(ToolModule):
    name = "vhost_discovery"
    domain = Domain.WEB
    stage = Stage.DISCOVERY
    requires = ()
    produces = ("subdomain",)
    tool = "ffuf"
    parser = "ffuf_vhost"
    input_type = None  # one fuzz pass per seed target domain
    output_ext = "txt"
    recursive = True   # re-feed found vhosts as seeds (depth from config)

    def command(self, tool, item, ctx) -> ToolInvocation:
        domain = host_of(item) or item
        wordlist = self._wordlist(ctx)
        return ToolInvocation(
            tool.argv(
                "-w", wordlist,
                "-u", f"https://{domain}/",
                "-H", f"Host: FUZZ.{domain}",
                "-ic",            # ignore wordlist comments
                "-ac",            # auto-calibrate — drop the catch-all baseline
                "-of", "json",
                "-o", "/dev/stdout",
                "-s",
            )
        )

    def refine_records(self, ctx, item, records: list) -> list:
        # Turn each matched FUZZ keyword into the full hostname FUZZ.<domain>.
        domain = host_of(item) or item
        for record in records:
            record.key = f"{record.key}.{domain}"
        return records

    def format_capture(self, raw_stdout: str) -> str:
        """Readable table: one vhost candidate per line with status/size."""
        if not raw_stdout.strip():
            return ""
        data = extract_ffuf_json(raw_stdout)
        if data is None:
            return raw_stdout
        results = data.get("results", [])
        lines = [f"# {len(results)} vhost candidate(s) | status  size  words  FUZZ"]
        for r in sorted(results, key=lambda x: (x.get("status", 0), -(x.get("length", 0) or 0))):
            fuzz = (r.get("input") or {}).get("FUZZ", "?")
            lines.append(
                f"  {str(r.get('status', '?')):>6}  {str(r.get('length', '?')):>9}  "
                f"{str(r.get('words', '?')):>6}  {fuzz}"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _wordlist(ctx) -> str:
        wordlists = ctx.config.wordlists.get("wordlists", {})
        entry = wordlists.get("vhosts") or {}
        return entry.get("path", _DEFAULT_WORDLIST)
