"""Hidden-parameter discovery (Phase 2) — mine candidates, then validate with arjun.

Endpoints rarely reveal every parameter they accept; the hidden ones (``debug``,
``accountId``, ``otpCode`` …) are prime IDOR/SQLi/SSRF surface. This stage finds
them in four steps, deterministic-first:

1. **JS mining** (:func:`analysis.params.mine_js_params`) over the JS bodies that
   ``js_fetch`` already cached — ``var``/``let``/``const`` names, object keys, and
   URL query params embedded in strings.
2. **Param reuse** (:func:`analysis.params.query_param_names`) — param *names*
   already seen on any discovered URL, pooled. Because the merged wordlist is run
   against EVERY endpoint, a param mined on endpoint A is automatically tested on
   endpoint B (cross-pollination) — no separate logic needed.
3. **Validate with arjun** — merged wordlist (built-in 25k ∪ mined ∪ reuse ∪ the
   ``ai_params`` AI seam) is fed to arjun, which binary-searches each endpoint and
   keeps only params that actually change the response.
4. **AI seam** (deferred) — an AI stage may later write
   ``results/<run_id>/ai_params.txt`` (context-aware extrapolation); it's folded in
   transparently, no change here.

arjun is **required** — a missing binary fails the stage (locked decision). Results
are written to ``results/<run_id>/params.{txt,json}`` (plus the candidate/wordlist/
target files for transparency). Discovered params are baked into each URL's query
string so the existing triage param scoring picks them up with no triage change.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from ...analysis.params import mine_js_params, query_param_names
from ...core.errors import ToolNotFoundError
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...engine import PARSERS, Normalizer, ParsedRecord
from ...engine.executor import redact_argv
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ...core.entities import Relation
from ..base import ToolModule, host_of, origin_of
from .js_fetch import load_bodies
from .parsers import bake_params

#: Statuses we treat as a responding endpoint worth fuzzing for params.
_LIVE_STATUSES = {200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308,
                  400, 401, 403, 405, 422, 500}
#: Static assets that never take parameters — skip them.
_SKIP_EXTS = (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
              ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
              ".mp4", ".mp3", ".avi", ".mov", ".webm", ".wasm", ".pdf")


@register
class ParamDiscovery(ToolModule):
    name = "param_discovery"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    # Needs URLs to fuzz AND the cached JS bodies (response) to mine candidates from,
    # so it must run AFTER js_fetch. Persists `url` assets directly but declares the
    # `param` sentinel instead of producing `url` — declaring `url` would cycle with
    # js_fetch/js_intel (same trick as permutation/content_subdomains/vhost).
    requires = ("url", "response")
    produces = ("param",)
    tool = "arjun"
    parser = "arjun"
    run_once = True            # expensive (active fuzzing) — once after discovery loop
    input_type = "url"

    # -- main flow ---------------------------------------------------------

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        log = get_logger("module.param_discovery", run_id=getattr(ctx, "run_id", None))

        if not self._spec(ctx).get("enabled", True):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"disabled": True}
            return result
        if ctx.executor is None or ctx.tools is None:
            raise NotImplementedError("engine services not available on context")
        if ctx.repository is None:
            raise NotImplementedError("persistence not available on context")

        engine = str(self._spec(ctx).get("engine", "arjun")).strip().lower() or "arjun"
        # Engine binary is required — a missing tool is a hard failure (no skip).
        try:
            tool = ctx.tools.resolve(engine)
        except ToolNotFoundError as exc:
            result.status = ModuleStatus.FAILED
            result.error = str(exc)
            return result

        endpoints = self._gather_inputs(ctx)
        if not endpoints:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"endpoints": 0}
            return result

        # Steps 1+2: deterministic candidates (JS-mined + reuse), plus AI seam.
        js_mined, reuse = self._mine_candidates(ctx)
        ai = set(self._extra_wordlist(ctx, "ai_params"))
        candidates = js_mined | reuse | ai
        base = self._base_words(ctx, engine)
        merged = list(dict.fromkeys([*base, *sorted(candidates)]))

        results_dir = getattr(ctx, "results_dir", None)
        self._write_candidates(results_dir, js_mined, reuse, ai)
        wordlist_path = self._write_lines(results_dir, "param_wordlist.txt", merged)
        targets_path = self._write_lines(results_dir, "param_targets.txt", endpoints)
        if not merged or wordlist_path is None or targets_path is None:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"endpoints": len(endpoints), "candidates": len(candidates),
                           "note": "no wordlist / no results dir"}
            return result

        # Step 3: validate with arjun, one pass per configured method.
        records = self._fuzz(ctx, tool, engine, targets_path, wordlist_path, results_dir)
        # Drop wildcard false-positives: on hosts that answer uniformly (SPA/redirect-
        # everything), arjun reports the SAME param on every endpoint (even static
        # files like robots.txt) — a param "valid" almost everywhere is noise, not a find.
        records, wildcard = self._filter_wildcard_params(ctx, records)
        records = [r for r in records if self._record_in_scope(ctx, r)]

        produced = 0
        if records:
            produced = ctx.repository.persist_normalization(
                ctx.run_id, Normalizer().normalize(records))["assets"]
        self._write_results(results_dir, records, js_mined, reuse, ai, engine)

        if wildcard:
            log.warning("param_discovery: dropped %d wildcard-FP param(s) seen on most "
                        "endpoints (uniform-response host): %s",
                        len(wildcard), ", ".join(sorted(wildcard)))
        log.info(
            "param_discovery: %d endpoint(s), %d candidate(s) (%d js, %d reuse, %d ai) "
            "-> %d endpoint(s) with params",
            len(endpoints), len(candidates), len(js_mined), len(reuse), len(ai), len(records),
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = produced
        result.meta = {"endpoints": len(endpoints), "candidates": len(candidates),
                       "with_params": len(records), "wildcard_dropped": sorted(wildcard)}
        return result

    def _filter_wildcard_params(self, ctx, records: list) -> tuple[list, set]:
        """Remove params that appear on >= ratio of endpoints (wildcard FPs).

        Mirrors dir_bruteforce's catch-all detection: a param the host "accepts"
        almost everywhere isn't a real per-endpoint parameter. Returns (kept records,
        dropped param names). Disabled for tiny endpoint sets where the ratio is
        meaningless. ``--stable`` on arjun reduces these upstream; this is the
        deterministic backstop regardless of engine/flags.
        """
        spec = self._spec(ctx)
        ratio = float(spec.get("wildcard_param_ratio", 0.8) or 0)
        min_ep = int(spec.get("wildcard_min_endpoints", 4))
        n = len(records)
        if n < min_ep or ratio <= 0:
            return records, set()
        counts: Counter = Counter()
        for r in records:
            for p in set(r.attributes.get("discovered_params", [])):
                counts[p] += 1
        wildcard = {p for p, c in counts.items() if c / n >= ratio}
        if not wildcard:
            return records, set()
        kept = []
        for r in records:
            params = [p for p in r.attributes.get("discovered_params", []) if p not in wildcard]
            if not params:
                continue   # this endpoint's only "params" were wildcard noise
            endpoint = r.key.split("?", 1)[0]
            method = r.attributes.get("param_method", "GET")
            baked = bake_params(endpoint, params)
            rec = ParsedRecord("url", baked,
                               attributes={"discovered_params": params, "param_method": method},
                               tool="arjun")
            origin = origin_of(baked)
            if origin:
                rec.relations.append(Relation("url", baked, "belongs_to", "host", origin))
            kept.append(rec)
        return kept, wildcard

    # -- step 0: pick endpoints --------------------------------------------

    def _gather_inputs(self, ctx) -> list[str]:
        """Live, de-duplicated-by-path, non-static endpoints, capped."""
        cap = int(self._spec(ctx).get("max_urls", 100) or 0)
        seen_path: set[str] = set()
        out: list[str] = []
        for asset in ctx.repository.list_assets(ctx.run_id, "url"):
            key = asset["canonical_key"]
            if not self._scope_ok(ctx, key):
                continue
            path = key.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith(_SKIP_EXTS):
                continue
            if not self._looks_like_real_url(key):
                continue   # drop crawler artifacts like /'+url+' or /').concat(...)
            if not self._is_live(self._attrs(asset.get("attributes_json"))):
                continue
            s = urlsplit(key)
            base = f"{s.scheme}://{s.netloc}{s.path}"   # dedupe by path, ignore query
            if base in seen_path:
                continue
            seen_path.add(base)
            out.append(base)
        return out[:cap] if cap else out

    #: Characters that mark a "URL" as a JS template/code artifact, not a real path.
    _JUNK_CHARS = set("'\"`{}()<>\\^| ")

    @classmethod
    def _looks_like_real_url(cls, url: str) -> bool:
        return not (cls._JUNK_CHARS & set(url))

    @staticmethod
    def _is_live(attrs: dict) -> bool:
        status = attrs.get("status_code")
        if status is None:
            methods = attrs.get("methods") or {}
            for info in methods.values():
                if (info or {}).get("status") is not None:
                    status = info["status"]
                    break
        try:
            return int(status) in _LIVE_STATUSES
        except (TypeError, ValueError):
            return False

    # -- steps 1+2: deterministic candidates -------------------------------

    def _mine_candidates(self, ctx) -> tuple[set[str], set[str]]:
        results_dir = getattr(ctx, "results_dir", None)
        js_mined: set[str] = set()
        for _url, body in load_bodies(results_dir):
            js_mined |= mine_js_params(body)
        reuse: set[str] = set()
        for asset in ctx.repository.list_assets(ctx.run_id, "url"):
            reuse |= query_param_names(asset["canonical_key"])
        return js_mined, reuse

    def _base_words(self, ctx, engine: str) -> list[str]:
        path = self._spec(ctx).get("wordlist")
        if not path:
            entry = (ctx.config.wordlists.get("wordlists", {}) or {}).get("params") or {}
            path = entry.get("path")
        if not path and engine == "arjun":
            path = self._arjun_builtin()
        if not path:
            return []
        try:
            lines = Path(path).read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        return [w.strip() for w in lines if w.strip() and not w.startswith("#")]

    @staticmethod
    def _arjun_builtin() -> str | None:
        try:
            import arjun
            p = Path(arjun.__file__).parent / "db" / "large.txt"
            return str(p) if p.exists() else None
        except Exception:
            return None

    # -- step 3: arjun fuzzing ---------------------------------------------

    def _fuzz(self, ctx, tool, engine, targets_path, wordlist_path, results_dir) -> list:
        parser = PARSERS.get(self.parser)
        log = get_logger("module.param_discovery", run_id=getattr(ctx, "run_id", None))
        methods = self._methods(ctx)
        spec = self._spec(ctx)
        # Param fuzzing is heavy (many endpoints x a big wordlist over possibly slow
        # hosts), so it gets its own timeout instead of the short executor default.
        timeout = float(spec.get("timeout_s", 1800))
        records: list = []
        for method in methods:
            out_file = Path(results_dir) / f"param_arjun-{method.lower()}.json"
            args = [
                "-i", str(targets_path),
                "-w", str(wordlist_path),
                "-m", method,
                "-oJ", str(out_file),
                "-t", str(int(spec.get("threads", 15))),
                "-T", str(int(spec.get("http_timeout_s", 15))),
                "-q",
            ]
            if spec.get("stable", False):   # --stable is markedly slower; opt-in
                args.append("--stable")
            if spec.get("chunk_size"):
                args += ["-c", str(int(spec["chunk_size"]))]
            argv = tool.argv(*args) + self._rate_args(ctx)
            exec_result = ctx.executor.run(argv, timeout_s=timeout)
            self._record_run(ctx, engine, argv, exec_result,
                             str(out_file) if out_file.exists() else None)
            if not exec_result.ok:
                if getattr(exec_result.status, "value", "") == "timeout":
                    log.warning(
                        "param_discovery: arjun -m %s timed out after %.0fs — lower "
                        "param_discovery.max_urls or raise timeout_s for slow targets.",
                        method, timeout,
                    )
                continue
            try:
                raw = out_file.read_text(encoding="utf-8")
            except OSError:
                continue
            records.extend(parser.parse(raw))
        return records

    def _methods(self, ctx) -> list[str]:
        configured = self._spec(ctx).get("methods") or ["GET"]
        out, seen = [], set()
        for m in configured:
            mu = str(m).strip().upper()
            if mu and mu not in seen:
                seen.add(mu)
                out.append(mu)
        return out or ["GET"]

    # -- output files ------------------------------------------------------

    def _write_lines(self, results_dir, name: str, lines: list[str]) -> str | None:
        if results_dir is None or not lines:
            return None
        path = Path(results_dir) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def _write_candidates(self, results_dir, js_mined, reuse, ai) -> None:
        """Transparency file: the deterministic+AI candidates before merge."""
        if results_dir is None:
            return
        rows = []
        for src, words in (("js_mined", js_mined), ("reuse", reuse), ("ai", ai)):
            for w in sorted(words):
                rows.append(f"{w}\t# {src}")
        path = Path(results_dir) / "param_candidates.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        total = len(js_mined | reuse | ai)
        header = (f"# {total} deterministic+AI candidate(s) before merge with builtin "
                  f"wordlist (js={len(js_mined)} reuse={len(reuse)} ai={len(ai)})\n")
        path.write_text(header + "\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")

    def _write_results(self, results_dir, records, js_mined, reuse, ai, engine) -> None:
        if results_dir is None:
            return

        def source_of(param: str) -> str:
            if param in js_mined:
                return "js_mined"
            if param in reuse:
                return "reuse"
            if param in ai:
                return "ai"
            return "builtin"

        txt_rows, json_rows = [], []
        for r in sorted(records, key=lambda x: x.key):
            params = r.attributes.get("discovered_params", [])
            method = r.attributes.get("param_method", "GET")
            url = r.key.split("?", 1)[0]
            txt_rows.append(f"{url}\t{method}\t{', '.join(params)}")
            json_rows.append({
                "url": url,
                "method": method,
                "params": params,
                "sources": {p: source_of(p) for p in params},
            })

        txt = Path(results_dir) / "params.txt"
        txt.parent.mkdir(parents=True, exist_ok=True)
        header = (f"# param_discovery — {len(txt_rows)} endpoint(s) with params, engine={engine}\n"
                  f"# endpoint\tmethod\tdiscovered params\n")
        txt.write_text(header + "\n".join(txt_rows) + ("\n" if txt_rows else ""), encoding="utf-8")
        (Path(results_dir) / "params.json").write_text(
            json.dumps(json_rows, indent=2), encoding="utf-8")

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _attrs(raw) -> dict:
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}

    def _record_run(self, ctx, tool, argv, exec_result, capture_path=None) -> None:
        if ctx.repository is None:
            return
        ctx.repository.record_tool_run(
            ctx.run_id, tool=tool, module=self.name, version=ctx.tools.version(tool),
            argv_redacted=redact_argv(argv), exit_code=exec_result.exit_code,
            status=exec_result.status.value, duration_s=exec_result.duration_s,
            capture_path=capture_path,
        )

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("param_discovery", {}) or {})
