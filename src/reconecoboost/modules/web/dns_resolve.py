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

import ipaddress
import os
import secrets
import tempfile
from pathlib import Path

from ...core.models import Domain, Stage
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, host_of

_DEFAULT_WORDLIST = "wordlists/dns/subdomains.txt"
_RESOLV_CONF = "/etc/resolv.conf"


def _system_resolvers() -> list[str]:
    """Nameservers from /etc/resolv.conf (the resolver the OS — and httpx — uses)."""
    try:
        text = Path(_RESOLV_CONF).read_text(encoding="utf-8")
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2 and parts[1] not in out:
                out.append(parts[1])
    return out


def dnsx_resolver_args(ctx) -> list[str]:
    """`-r <ns,...>` for dnsx, shared by dns_resolve + permutation.

    dnsx defaults to public resolvers (1.1.1.1/8.8.8.8); when outbound UDP 53 to
    those is blocked (corporate/filtered networks) it silently resolves nothing
    while httpx — which uses the OS resolver — still works. So we point dnsx at the
    **system resolver** by default. Override with ``dns_resolve.resolvers`` (a list);
    an empty list falls back to dnsx's own defaults.
    """
    dns_cfg = (ctx.config.pipeline.get("dns_resolve", {}) or {})
    resolvers = dns_cfg.get("resolvers")
    if resolvers is None:                       # not configured -> use the OS resolver
        resolvers = _system_resolvers()
    resolvers = [str(r).strip() for r in (resolvers or []) if str(r).strip()]
    return ["-r", ",".join(resolvers)] if resolvers else []


# --------------------------------------------------------------------------- #
# Network position preference (public / internal / both)                        #
# --------------------------------------------------------------------------- #
# Hosts can resolve to public IPs, RFC1918 internal IPs, or both. Where you run
# the tool decides which are reachable: from the internet only public IPs work;
# from inside the network internal IPs work too. `dns_resolve.prefer` controls it
# and is honoured by alive_detection (which hosts to probe) and vhost_discovery
# (which IPs to fuzz):
#   public   (default) probe public IPs; internal-only hosts skipped (kept as intel)
#   internal probe everything; for hosts with both, focus on the internal IP
#   both     probe everything; use all IPs


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def network_preference(ctx) -> str:
    pref = str((ctx.config.pipeline.get("dns_resolve", {}) or {}).get("prefer", "public")).strip().lower()
    return pref if pref in ("public", "internal", "both") else "public"


def _position(attrs: dict) -> tuple[bool, bool]:
    """(has_public_ip, has_private_ip) for a resolved subdomain's attributes."""
    ips = attrs.get("ip") or []
    if ips:
        has_priv = any(_is_private(ip) for ip in ips)
        has_pub = any(not _is_private(ip) for ip in ips)
        return has_pub, has_priv
    if attrs.get("internal"):            # flagged internal-only, no ip list kept
        return False, True
    if attrs.get("internal_ips"):        # mixed: reachable publicly + leaks internal
        return True, True
    return True, False                   # unknown (e.g. content-discovered) -> treat reachable


def host_reachable(attrs: dict, prefer: str) -> bool:
    """Whether to actively probe this host given the network preference."""
    has_pub, _has_priv = _position(attrs)
    if prefer in ("internal", "both"):
        return True      # positioned inside the network -> probe everything
    return has_pub       # public preference: internal-only hosts aren't reachable


def family_ips(ips: list[str], prefer: str) -> list[str]:
    """The IP subset to actually target given the preference."""
    if prefer == "both":
        return list(ips)
    priv = [ip for ip in ips if _is_private(ip)]
    pub = [ip for ip in ips if not _is_private(ip)]
    return priv if prefer == "internal" else pub


@register
class DnsResolve(ToolModule):
    name = "dns_resolve"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("subdomain", "ai_subwords")   # ai_subwords = optional edge (only when AI on)
    produces = ("subdomain",)
    tool = "dnsx"
    parser = "dnsx"
    input_type = "subdomain"
    batch = True
    # NOT recursive: brute targets the APEX (word.<apex>), so re-feeding found
    # subdomains would just re-brute the same apex. Sub-of-sub expansion is handled
    # by permutation (alterx) + the discovery loop, not by multiplying word×subs here.
    recursive = False
    output_ext = "jsonl"

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
        # NOTE: dnsx `-wd` is a special mode that ignores stdin/other flags and
        # produces no output for our use — do NOT use it. Plain resolve here;
        # wildcard filtering is done by us in refine_records.
        argv = tool.argv("-silent", "-json", "-a") + dnsx_resolver_args(ctx)
        probes = (sorted(self._wildcard_probes(ctx))
                  if self._spec(ctx).get("wildcard_filter", True) else [])

        if not self._brute_active(ctx):
            # Resolve-only: small set — feed via stdin.
            names = list(dict.fromkeys(list(items) + probes))
            return ToolInvocation(argv, input_text="\n".join(names))

        # WILDCARD SHORT-CIRCUIT: if the apex has a wildcard DNS record, EVERY brute
        # candidate resolves (to the catch-all) — 100% false positives + millions of
        # wasted queries. Detect it up-front (cheap: resolve a couple of random names)
        # and skip the brute entirely; we still resolve the known names (real subs
        # are kept, wildcard-only ones dropped in refine_records).
        if self._brute(ctx).get("skip_on_wildcard", True) and self._has_wildcard(ctx, tool):
            get_logger("module.dns_resolve", run_id=getattr(ctx, "run_id", None)).warning(
                "dns_resolve: wildcard DNS detected on the apex — SKIPPING brute (every "
                "name would resolve to the catch-all). Resolving known names only. "
                "Set dns_resolve.brute.skip_on_wildcard: false to force it.")
            names = list(dict.fromkeys(list(items) + probes))
            return ToolInvocation(argv, input_text="\n".join(names))

        # Brute: candidates = wordlist × APEX (not × every discovered sub — that
        # multiplies into hundreds of millions). The candidates are STREAMED to a
        # file and dnsx reads it with `-l`, so the FULL wordlist (even millions of
        # lines) runs without ever living in memory or a giant stdin string.
        path = self._write_candidate_file(ctx, items, probes)
        if path is None:   # no writable dir (e.g. unit test) — fall back to stdin
            names = list(dict.fromkeys(list(items) + probes))
            return ToolInvocation(argv, input_text="\n".join(names))
        return ToolInvocation(argv + ["-l", path])

    def _write_candidate_file(self, ctx, items, probes) -> str | None:
        """Stream resolve targets + (wordlist × apex) brute candidates to a file.

        O(1) memory: the wordlist is read line-by-line and written straight out, so
        list size is bounded only by disk + dnsx throughput, not RAM. ``max_candidates``
        (optional) caps the brute count; unset = the whole wordlist.
        """
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is not None:
            path = Path(results_dir) / "dns_candidates.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            fd, tmp = tempfile.mkstemp(prefix="dns_candidates-", suffix=".txt")
            os.close(fd)
            path = Path(tmp)

        brute = self._brute(ctx)
        cap = int(brute.get("max_candidates", 0) or 0)   # 0/unset = no cap (streaming-safe)
        apexes = list(dict.fromkeys(host_of(t) or t for t in ctx.scope.targets))
        ai_words = self._extra_wordlist(ctx, "ai_subwords")   # AI seam (Phase 0)
        wl_path = brute.get("wordlist") or _DEFAULT_WORDLIST

        written = 0
        seen_small = set()
        with path.open("w", encoding="utf-8") as fh:
            for n in list(items) + probes:                # resolve known names + probes (small)
                if n and n not in seen_small:
                    seen_small.add(n)
                    fh.write(n + "\n")
            for apex in apexes:                           # brute: word.<apex>, streamed
                for w in self._stream_words(wl_path):
                    fh.write(f"{w}.{apex}\n")
                    written += 1
                    if cap and written >= cap:
                        break
                for w in ai_words:
                    fh.write(f"{w}.{apex}\n")
                if cap and written >= cap:
                    break
        return str(path)

    @staticmethod
    def _stream_words(path: str):
        """Yield cleaned wordlist entries one at a time (no full-file load)."""
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    w = line.strip()
                    if w and not w.startswith("#"):
                        yield w
        except OSError:
            return

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

    def _has_wildcard(self, ctx, tool) -> bool:
        """Cheap up-front wildcard check: resolve a few RANDOM names under each apex.
        If any resolves, the apex has a wildcard/catch-all DNS record (dnsx -silent
        emits only resolving hosts, so non-empty stdout = wildcard)."""
        if ctx.executor is None:
            return False
        probes = []
        for target in ctx.scope.targets:
            apex = host_of(target) or target
            if not apex:
                continue
            for _ in range(2):
                probes.append(f"zz{secrets.token_hex(10)}-nx.{apex}")
        if not probes:
            return False
        argv = tool.argv("-silent", "-json", "-a") + dnsx_resolver_args(ctx)
        res = ctx.executor.run(argv, timeout_s=60, input_text="\n".join(probes))
        return bool(res.ok and res.stdout.strip())

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
