"""Directory brute-force with ffuf, across one or more HTTP methods."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from ...core.models import Domain, Stage
from ...engine import ParsedRecord
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ..base import ToolInvocation, ToolModule, origin_of

_DEFAULT_WORDLIST = "wordlists/ffuf/directories.txt"
_DEFAULT_METHODS = ["GET"]

#: A host is flagged as a likely catch-all when this fraction of its results
#: share one response size (and it has at least this many results).
_CATCHALL_RATIO = 0.8
_CATCHALL_MIN = 10
#: Per host, log at most this many individual results (the rest are in the DB).
_LOG_LIMIT = 20


@register
class DirBruteforce(ToolModule):
    name = "dir_bruteforce"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("host",)
    produces = ("url",)
    tool = "ffuf"
    parser = "ffuf"
    run_once = True   # expensive + writes findings — once after the discovery loop
    input_type = "host"
    output_ext = "txt"  # saved as a readable table, not ffuf's raw JSON blob

    # -- one ffuf invocation per configured HTTP method --------------------

    def commands(self, tool, item, ctx) -> list[ToolInvocation]:
        wordlist = self._wordlist(ctx)
        target = item.rstrip("/") + "/FUZZ"
        invs = []
        for method in self._methods(ctx):
            invs.append(ToolInvocation(tool.argv(
                "-u", target,
                "-w", wordlist,
                "-X", method,        # the HTTP method under test
                "-ic",               # ignore '#' comment lines in the wordlist
                "-of", "json",
                "-o", "/dev/stdout",
                "-s",
            )))
        return invs

    @staticmethod
    def _methods(ctx) -> list[str]:
        ffuf = (ctx.config.tools.get("tools", {}) or {}).get("ffuf", {}) or {}
        configured = ffuf.get("methods") or _DEFAULT_METHODS
        out, seen = [], set()
        for m in configured:
            mu = str(m).strip().upper()
            if mu and mu not in seen:
                seen.add(mu)
                out.append(mu)
        return out or list(_DEFAULT_METHODS)

    def _wordlist(self, ctx) -> str:
        wordlists = ctx.config.wordlists.get("wordlists", {})
        entry = wordlists.get("directories") or wordlists.get("common") or {}
        base = entry.get("path", _DEFAULT_WORDLIST)
        extra = self._extra_wordlist(ctx, "ai_dirwords")   # AI seam (Phase 0)
        if not extra:
            return base
        return self._merged_wordlist(ctx, base, extra)

    def _merged_wordlist(self, ctx, base: str, extra: list[str]) -> str:
        """Write base ∪ AI-suggested paths to one file ffuf can consume.

        ffuf takes a single ``-w`` file per keyword, so AI words are merged with
        the base list (deduped, order-preserving) into ``results/<run_id>/
        dir_wordlist_merged.txt``. Falls back to ``base`` if there's no results dir.
        """
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return base
        words: list[str] = []
        try:
            words += Path(base).read_text(encoding="utf-8").splitlines()
        except OSError:
            pass
        words += extra
        merged = list(dict.fromkeys(w.strip() for w in words if w.strip()))
        path = Path(results_dir) / "dir_wordlist_merged.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(merged) + "\n", encoding="utf-8")
        return str(path)

    # -- fold per-method results for the same URL into one record ----------

    def finalize_records(self, ctx, records: list) -> list:
        folded: dict[str, ParsedRecord] = {}
        order: list[str] = []
        others = []
        for record in records:
            if record.asset_type != "url":
                others.append(record)
                continue
            key = record.key
            if key not in folded:
                folded[key] = ParsedRecord(
                    "url", key, attributes={"methods": {}},
                    tool=record.tool, relations=list(record.relations),
                )
                order.append(key)
            method = record.attributes.get("method", "GET")
            folded[key].attributes["methods"][method] = {
                k: record.attributes[k]
                for k in ("status", "length", "words", "content-type", "redirectlocation")
                if k in record.attributes
            }
        return [folded[k] for k in order] + others

    # Per-invocation capture is disabled: one consolidated file per host is
    # written in after_persist instead (all methods together), so results are
    # easy to manage rather than split into one file per (host, method).
    def _write_capture(self, ctx, index, exec_result):
        return None

    # -- one consolidated file per host + logging + catch-all detection ----

    def after_persist(self, ctx, entities) -> None:
        log = get_logger("module.dir_bruteforce", run_id=ctx.run_id)
        results_dir = getattr(ctx, "results_dir", None)

        # Flatten to (url, method, status, size, words) grouped per host.
        by_host: dict[str, list] = defaultdict(list)
        for entity in entities:
            if entity.asset_type != "url":
                continue
            host = origin_of(entity.canonical_key) or "?"
            for method, data in (entity.attributes.get("methods") or {}).items():
                by_host[host].append((
                    entity.canonical_key, method,
                    data.get("status"), data.get("length"), data.get("words"),
                ))

        for host, hits in by_host.items():
            statuses = Counter(h[2] for h in hits)
            sizes = Counter(h[3] for h in hits)
            log.info("dir_bruteforce %s: %d results, status=%s", host, len(hits), dict(statuses))

            top_size, top_n = sizes.most_common(1)[0]
            if len(hits) >= _CATCHALL_MIN and top_n / len(hits) >= _CATCHALL_RATIO:
                log.warning(
                    "dir_bruteforce %s: %d/%d results share size=%s — likely catch-all "
                    "(probable false positives; consider ffuf -ac or tighter filtering)",
                    host, top_n, len(hits), top_size,
                )
                if ctx.repository is not None:
                    ctx.repository.add_finding(
                        ctx.run_id, kind="recon_note",
                        title=f"Possible catch-all directory responses on {host}",
                        severity="info",
                        detail={"host": host, "shared_size": top_size,
                                "shared_count": top_n, "total_results": len(hits),
                                "note": "Most fuzzed paths returned the same size — likely "
                                        "false positives."},
                        source="dir_bruteforce",
                    )

            for url, method, status, size, _w in hits[:_LOG_LIMIT]:
                log.info("  [%s] %s [status=%s size=%s]", method, url, status, size)
            if len(hits) > _LOG_LIMIT:
                log.info("  ... and %d more (full list in the DB/report)", len(hits) - _LOG_LIMIT)

            if results_dir is not None:
                self._write_host_file(Path(results_dir), host, hits)

    @staticmethod
    def _write_host_file(results_dir: Path, host: str, hits: list) -> None:
        """Write ONE readable file per host with every (method, url) result."""
        label = host.split("://", 1)[-1].replace(":", "_").strip("/") or "host"
        methods = sorted({h[1] for h in hits})
        urls = {h[0] for h in hits}
        lines = [
            f"# dir_bruteforce {host} — {len(urls)} url(s), methods: {', '.join(methods)}",
            f"# {'status':>6}  {'size':>9}  {'words':>6}  {'method':>7}  url",
        ]
        # group by url so each endpoint's methods sit together (easy to compare)
        for url, method, status, size, words in sorted(hits, key=lambda x: (x[0], x[1])):
            lines.append(
                f"  {str(status):>6}  {str(size):>9}  {str(words):>6}  {method:>7}  {url}"
            )
        path = results_dir / f"dir_bruteforce-{label}.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
