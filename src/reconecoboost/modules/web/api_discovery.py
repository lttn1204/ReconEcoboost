"""API discovery (Phase 3) — probe for OpenAPI/Swagger specs and GraphQL endpoints.

HTML crawling rarely reveals a backend's full API surface. This stage actively
probes each live host for well-known API-spec paths (``/openapi.json``,
``/v2/api-docs``, ``/swagger.json`` …) and GraphQL endpoints (``/graphql`` …):

* An exposed **OpenAPI/Swagger** spec is parsed (:func:`analysis.openapi.parse_openapi`)
  into its endpoints + params → emitted as ``url`` assets (baked with params so
  triage/param_discovery pick them up) + a finding. This unearths endpoints no
  crawler would find.
* A reachable **GraphQL** endpoint is recorded + flagged (introspection follow-up
  is left to the operator).

Uses httpx (already required everywhere). Persists ``url`` assets directly but
declares the ``api`` sentinel to avoid a DAG cycle with the url producers/consumers
(same trick as param_discovery/permutation). Results: results/<run_id>/api.{txt,json}.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...analysis.openapi import extract_http_body, looks_like_graphql, parse_openapi
from ...core.errors import ToolNotFoundError
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...engine import Normalizer, ParsedRecord
from ...engine.executor import redact_argv
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ...core.entities import Relation
from ..base import ToolModule, origin_of
from .parsers import bake_params

# Well-known OpenAPI/Swagger spec locations.
_OPENAPI_PATHS = (
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api-docs.json",
    "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
    "/swagger/index.html", "/swagger-ui.html", "/docs/swagger.json",
)
# Well-known GraphQL endpoints.
_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/graphql/console", "/graphiql")

# Statuses worth inspecting (200 = spec; 400/401/403/405 = gated/graphql-ish).
_MATCH_CODES = "200,400,401,403,405"


@register
class ApiDiscovery(ToolModule):
    name = "api_discovery"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("host",)
    produces = ("api",)          # persists `url` assets directly; sentinel avoids DAG cycle
    tool = "httpx"
    parser = None
    input_type = "host"

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        log = get_logger("module.api_discovery", run_id=getattr(ctx, "run_id", None))

        if not self._spec(ctx).get("enabled", True):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"disabled": True}
            return result
        if ctx.executor is None or ctx.tools is None or ctx.repository is None:
            raise NotImplementedError("engine services / persistence not available on context")
        try:
            tool = ctx.tools.resolve(self.tool)
        except ToolNotFoundError as exc:   # httpx is base plumbing — degrade gracefully
            result.status = ModuleStatus.SKIPPED
            result.error = str(exc)
            return result

        hosts = self._hosts(ctx)
        if not hosts:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"hosts": 0}
            return result

        candidates = self._candidates(ctx, hosts)
        responses = self._probe(ctx, tool, candidates)

        records, findings = self._analyze(responses)
        records = [r for r in records if self._record_in_scope(ctx, r)]

        produced = 0
        if records:
            produced = ctx.repository.persist_normalization(
                ctx.run_id, Normalizer().normalize(records))["assets"]
        for f in findings:
            ctx.repository.add_finding(ctx.run_id, source=self.name, **f)
        self._write_results(ctx, records, findings)

        log.info("api_discovery: %d host(s), %d probe(s) -> %d endpoint(s), %d finding(s)",
                 len(hosts), len(candidates), len(records), len(findings))
        result.status = ModuleStatus.SUCCESS
        result.produced = produced
        result.meta = {"hosts": len(hosts), "probes": len(candidates),
                       "endpoints": len(records), "findings": len(findings)}
        return result

    # -- inputs ------------------------------------------------------------

    def _hosts(self, ctx) -> list[str]:
        cap = int(self._spec(ctx).get("max_hosts", 50) or 0)
        out, seen = [], set()
        for asset in ctx.repository.list_assets(ctx.run_id, "host"):
            key = asset["canonical_key"]
            if "://" not in key or not self._scope_ok(ctx, key):
                continue
            if key not in seen:
                seen.add(key)
                out.append(key)
        return out[:cap] if cap else out

    def _candidates(self, ctx, hosts: list[str]) -> list[str]:
        spec = self._spec(ctx)
        openapi = list(_OPENAPI_PATHS) + list(spec.get("extra_paths", []) or [])
        paths = list(openapi)
        if spec.get("graphql", True):
            paths += list(_GRAPHQL_PATHS)
        out, seen = [], set()
        for host in hosts:
            base = host.rstrip("/")
            for p in paths:
                url = base + p
                if url not in seen:
                    seen.add(url)
                    out.append(url)
        return out

    # -- probe -------------------------------------------------------------

    def _probe(self, ctx, tool, candidates: list[str]) -> list[dict]:
        if not candidates:
            return []
        timeout = int(self._spec(ctx).get("http_timeout_s", 15))
        argv = tool.argv("-silent", "-json", "-irr", "-t", str(timeout),
                         "-mc", _MATCH_CODES) + self._rate_args(ctx)
        stage_timeout = float(self._spec(ctx).get("timeout_s", 900))
        exec_result = ctx.executor.run(argv, timeout_s=stage_timeout,
                                       input_text="\n".join(candidates))
        capture = self._write_capture_text(ctx, "api_discovery", exec_result)
        self._record_run(ctx, argv, exec_result, capture)
        if not exec_result.ok:
            return []
        out = []
        for line in exec_result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    # -- analyze -----------------------------------------------------------

    def _analyze(self, responses: list[dict]) -> tuple[list, list[dict]]:
        records: list = []
        findings: list[dict] = []
        for obj in responses:
            url = obj.get("input") or obj.get("url")
            if not url:
                continue
            status = obj.get("status_code")
            body = extract_http_body(obj.get("response") or obj.get("raw") or obj.get("body") or "")
            path = url.split("?", 1)[0]
            api_base = origin_of(url)   # scheme://host

            if any(path.endswith(p) for p in _OPENAPI_PATHS) and status == 200:
                endpoints = parse_openapi(body)
                if endpoints and api_base:
                    records.append(self._url_record(url, [], source="openapi_spec"))
                    for ep in endpoints:
                        full = api_base + ep["path"]
                        records.append(self._url_record(full, ep["params"],
                                                        method=ep["method"], source="openapi"))
                    findings.append({
                        "kind": "exposed_api_spec", "severity": "medium",
                        "title": f"Exposed API specification at {url}",
                        "detail": {"url": url, "endpoints": len(endpoints),
                                   "note": "OpenAPI/Swagger spec is publicly readable; "
                                           "enumerate the listed endpoints/params."},
                    })
            elif any(path.endswith(p) for p in _GRAPHQL_PATHS) and looks_like_graphql(body, status):
                records.append(self._url_record(url, [], source="graphql"))
                findings.append({
                    "kind": "graphql_endpoint", "severity": "low",
                    "title": f"GraphQL endpoint reachable at {url}",
                    "detail": {"url": url, "status": status,
                               "note": "Check introspection (e.g. a __schema query) and "
                                       "authorization on queries/mutations."},
                })
        return records, findings

    @staticmethod
    def _url_record(url: str, params: list[str], *, method: str = "GET", source: str) -> ParsedRecord:
        baked = bake_params(url, params)
        attrs = {"api_source": source}
        if params:
            attrs["discovered_params"] = params
            attrs["param_method"] = method
        rec = ParsedRecord("url", baked, attributes=attrs, tool="api_discovery")
        origin = origin_of(baked)
        if origin:
            rec.relations.append(Relation("url", baked, "belongs_to", "host", origin))
        return rec

    # -- output ------------------------------------------------------------

    def _write_results(self, ctx, records, findings) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        rows = []
        for r in sorted(records, key=lambda x: x.key):
            src = r.attributes.get("api_source", "")
            params = ", ".join(r.attributes.get("discovered_params", []))
            method = r.attributes.get("param_method", "")
            rows.append(f"{r.key}\t{src}\t{method}\t{params}".rstrip())
        path = Path(results_dir) / "api.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        header = (f"# api_discovery — {len(records)} endpoint(s), {len(findings)} finding(s)\n"
                  f"# url\tsource\tmethod\tparams\n")
        path.write_text(header + "\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
        (Path(results_dir) / "api.json").write_text(
            json.dumps({"findings": findings,
                        "endpoints": [{"url": r.key,
                                       "source": r.attributes.get("api_source"),
                                       "params": r.attributes.get("discovered_params", [])}
                                      for r in records]}, indent=2), encoding="utf-8")

    def _write_capture_text(self, ctx, label, exec_result) -> str | None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None or not exec_result.ok or not exec_result.stdout:
            return None
        path = Path(results_dir) / f"{label}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(exec_result.stdout, encoding="utf-8")
        return str(path)

    def _record_run(self, ctx, argv, exec_result, capture_path=None) -> None:
        if ctx.repository is None:
            return
        ctx.repository.record_tool_run(
            ctx.run_id, tool=self.tool, module=self.name, version=ctx.tools.version(self.tool),
            argv_redacted=redact_argv(argv), exit_code=exec_result.exit_code,
            status=exec_result.status.value, duration_s=exec_result.duration_s,
            capture_path=capture_path,
        )

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("api_discovery", {}) or {})
