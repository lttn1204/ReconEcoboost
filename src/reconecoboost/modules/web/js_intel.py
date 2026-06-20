"""JS intelligence stage — mine endpoints/hosts/cloud URLs from JavaScript.

leaklens-style ``--js-intel`` as a separate, toggleable module (config
``js_intel.enabled``). Bodies are fetched once by ``js_fetch``; this stage reads
them and runs ``analysis.js_intel``, then:

* persists discovered **endpoints** as ``url`` assets and in-scope **hosts** as
  ``subdomain`` assets — so they show up in the graph / triage / AI / report;
* emits ``finding`` rows for **cloud buckets** and exposed **source maps**.

It declares ``produces=("finding",)`` only (not url/subdomain) on purpose: the
discovered assets are persisted directly, but declaring them would create a DAG
cycle (subdomain → alive → crawl → js_fetch → js_intel → subdomain). Zero tokens.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from ...analysis.js_intel import extract
from ...core.entities import Relation
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...core.module import BaseModule
from ...engine import Normalizer, ParsedRecord
from ...logging.setup import get_logger
from ...orchestration.registry import register
from .js_fetch import load_bodies


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else url


@register
class JsIntel(BaseModule):
    name = "js_intel"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("response",)   # bodies fetched by js_fetch
    produces = ("finding",)    # url/subdomain persisted directly (avoid DAG cycle)
    tool = None
    parser = None

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        spec = self._spec(ctx)
        if not spec.get("enabled", True):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"disabled": True}
            return result
        if ctx.repository is None:
            raise NotImplementedError("persistence not available on context")

        bodies = load_bodies(getattr(ctx, "results_dir", None))
        if not bodies:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"bodies": 0}
            return result

        intel = self._extract(ctx, bodies)
        produced = self._persist(ctx, intel)
        self._write_results(ctx, intel)
        get_logger("module.js_intel", run_id=ctx.run_id).info(
            "js_intel: %d body(ies), %d endpoint(s), %d host(s), %d cloud, %d sourcemap(s)",
            len(bodies), len(intel["endpoints"]), len(intel["hosts"]),
            len(intel["cloud"]), len(intel["sourcemaps"]),
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = produced
        result.meta = {"bodies": len(bodies), **{k: len(v) for k, v in intel.items()}}
        return result

    # -- helpers -----------------------------------------------------------

    def _extract(self, ctx, bodies: list[tuple[str, str]]) -> dict:
        max_per_file = int(self._spec(ctx).get("max_per_file", 200) or 200)
        endpoints: dict[str, str] = {}   # full_url -> origin
        hosts: set[str] = set()
        cloud: set[str] = set()
        sourcemaps: dict[str, str] = {}
        for url, body in bodies:
            origin = _origin(url)
            found = extract(body, max_endpoints=max_per_file)
            for path in found.endpoints:
                endpoints[urljoin(origin + "/", path)] = origin
            hosts.update(found.hosts)
            cloud.update(found.cloud)
            for sm in found.sourcemaps:
                sourcemaps[urljoin(url, sm)] = origin
        return {
            "endpoints": [{"url": u, "origin": o} for u, o in endpoints.items()],
            "hosts": sorted(hosts),
            "cloud": sorted(cloud),
            "sourcemaps": [{"url": u, "origin": o} for u, o in sourcemaps.items()],
        }

    def _persist(self, ctx, intel: dict) -> int:
        repo = ctx.repository
        records: list[ParsedRecord] = []
        for ep in intel["endpoints"]:
            records.append(ParsedRecord(
                "url", ep["url"], tool="js_intel",
                relations=[Relation("url", ep["url"], "belongs_to", "host", ep["origin"])],
            ))
        for host in intel["hosts"]:
            if ctx.scope.is_allowed(host):
                records.append(ParsedRecord("subdomain", host, tool="js_intel"))
        if records:
            repo.persist_normalization(ctx.run_id, Normalizer().normalize(records))

        produced = len(records)
        for bucket in intel["cloud"]:
            repo.add_finding(ctx.run_id, kind="exposure", title=f"Cloud storage URL in JS: {bucket}",
                             severity="medium", detail={"url": bucket, "type": "cloud_storage"},
                             source="js_intel")
            produced += 1
        for sm in intel["sourcemaps"]:
            repo.add_finding(ctx.run_id, kind="exposure", title=f"Exposed source map: {sm['url']}",
                             severity="low", detail={"url": sm["url"], "type": "source_map"},
                             source="js_intel")
            produced += 1
        return produced

    def _write_results(self, ctx, intel: dict) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        out = Path(results_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "js_intel.json").write_text(json.dumps(intel, indent=2), encoding="utf-8")
        lines = ["# endpoints"] + [e["url"] for e in intel["endpoints"]]
        lines += ["", "# hosts"] + intel["hosts"]
        lines += ["", "# cloud"] + intel["cloud"]
        lines += ["", "# source maps"] + [s["url"] for s in intel["sourcemaps"]]
        (out / "js_intel.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("js_intel", {}) or {})
