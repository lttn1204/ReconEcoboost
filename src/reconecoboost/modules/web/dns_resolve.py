"""DNS resolution + (recursive) brute-force with dnsx.

One dnsx pass per level:
1. **Resolve** known subdomains (subfinder/vhost/seed) — attach IP(s), flag
   `internal` (RFC1918/loopback), filter wildcard DNS.
2. **Brute** (config `dns_resolve.brute`): generate `word.<name>` under every known
   name and resolve them. Only resolving names become subdomain assets.

**Recursive** (like asset_discovery): names found at one level are brute-expanded
again at the next, up to `dns_resolve.brute.depth`. Brute runs only on a wildcard
scope. Rate is the standard dnsx `-rl` (tools.yaml: dnsx.rate_limit / defaults).
Resolving summary -> results/<run_id>/dns_resolve.txt.
"""

from __future__ import annotations

from pathlib import Path

from ...core.models import Domain, Stage
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of

_DEFAULT_WORDLIST = "wordlists/dns/subdomains.txt"


@register
class DnsResolve(ToolModule):
    name = "dns_resolve"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("subdomain",)
    produces = ("subdomain",)
    tool = "dnsx"
    parser = "dnsx"
    input_type = "subdomain"
    batch = True
    recursive = True          # brute sub-of-sub across levels (depth from config)
    output_ext = "jsonl"

    def _recursion_depth(self, ctx) -> int:
        # Recursion only matters when brute is active; otherwise a single pass.
        if not self._brute_active(ctx):
            return 1
        try:
            return max(1, int(self._brute(ctx).get("depth", 1) or 1))
        except (TypeError, ValueError):
            return 1

    def _gather_inputs(self, ctx) -> list[str]:
        """Known names to resolve + brute under: discovered subdomains + apexes."""
        names = list(super()._gather_inputs(ctx))          # subdomain assets
        names += [host_of(t) or t for t in ctx.scope.targets]
        seen, out = set(), []
        for n in names:
            if n and n not in seen:
                seen.add(n)
                out.append(n)
        return out

    def batch_command(self, tool, items, ctx) -> ToolInvocation:
        names = list(items)
        if self._brute_active(ctx):
            words = self._load_words(self._brute(ctx))
            words += self._extra_wordlist(ctx, "ai_subwords")   # AI seam (Phase 0)
            generated = [f"{w}.{n}" for n in items for w in dict.fromkeys(words)]
            cap = int(self._brute(ctx).get("max_candidates", 0) or 0)
            if cap:
                generated = generated[:cap]
            names += generated

        # Wildcard detection: add synthetic non-existent hosts; whatever IP they
        # resolve to is the wildcard catch-all (filtered out in refine_records).
        if self._spec(ctx).get("wildcard_filter", True):
            names += sorted(self._wildcard_probes(ctx))

        seen, uniq = set(), []
        for n in names:
            if n not in seen:
                seen.add(n)
                uniq.append(n)

        # NOTE: dnsx `-wd` is a special mode that ignores stdin/other flags and
        # produces no output for our use — do NOT use it. Plain resolve here;
        # wildcard filtering is done by us in refine_records.
        argv = tool.argv("-silent", "-json", "-a")
        return ToolInvocation(argv, input_text="\n".join(uniq))

    def refine_records(self, ctx, item, records: list) -> list:
        """Drop wildcard-DNS false positives + the synthetic probe hosts."""
        if not self._spec(ctx).get("wildcard_filter", True):
            return records
        probes = self._wildcard_probes(ctx)
        wildcard_ips: set[str] = set()
        for r in records:
            if r.key in probes:
                wildcard_ips.update(r.attributes.get("ip", []))
        out = []
        for r in records:
            if r.key in probes:
                continue  # synthetic probe — never a real asset
            ips = set(r.attributes.get("ip", []))
            if wildcard_ips and ips and ips <= wildcard_ips:
                continue  # resolves only to the wildcard IP(s) — false positive
            out.append(r)
        return out

    @staticmethod
    def _wildcard_probes(ctx) -> set[str]:
        probes: set[str] = set()
        for target in ctx.scope.targets:
            apex = host_of(target) or target
            for i in range(3):
                probes.add(f"zzz-wildcardcheck{i}-doesnotexist.{apex}")
        return probes

    def after_persist(self, ctx, entities) -> None:
        """Write a human-readable summary of resolved subdomains to results/."""
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        rows = []
        for e in entities:
            attrs = e.attributes or {}
            if e.asset_type != "subdomain" or not attrs.get("resolved"):
                continue
            ips = ", ".join(attrs.get("ip", []))
            tag = "  [internal]" if attrs.get("internal") else ""
            rows.append(f"{e.canonical_key}\t{ips}{tag}")
        path = Path(results_dir) / "dns_resolve.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        header = f"# {len(rows)} resolved subdomain(s) | host <tab> IP(s) [internal]\n"
        path.write_text(header + "\n".join(sorted(rows)) + ("\n" if rows else ""), encoding="utf-8")

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("dns_resolve", {}) or {})

    def _brute(self, ctx) -> dict:
        return self._spec(ctx).get("brute", {}) or {}

    def _brute_active(self, ctx) -> bool:
        # Active subdomain brute only on a wildcard scope (`*.domain`); an explicit
        # exact-host scope means "just these" — skip, as designed.
        return bool(self._brute(ctx).get("enabled", True)) and self._scope_has_wildcard(ctx.scope)

    @staticmethod
    def _scope_has_wildcard(scope) -> bool:
        pools = list(scope.in_scope or []) + list(scope.targets or [])
        return any("*" in str(p) for p in pools)

    @staticmethod
    def _load_words(brute: dict) -> list[str]:
        path = brute.get("wordlist") or _DEFAULT_WORDLIST
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        return [w.strip() for w in lines if w.strip() and not w.startswith("#")]
