"""Tests for Phase 3 API discovery: OpenAPI parsing, GraphQL detection, the module."""

import json

from reconecoboost.analysis.openapi import (
    extract_http_body,
    looks_like_graphql,
    parse_openapi,
)
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.errors import ToolNotFoundError
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import (
    ExecutionResult,
    ExecutionStatus,
    Normalizer,
    ParsedRecord,
    ToolHandle,
)
from reconecoboost.modules.web.api_discovery import ApiDiscovery
from reconecoboost.persistence import Database, Store


# --- pure helpers ----------------------------------------------------------
def test_parse_openapi_v3_and_v2():
    v3 = json.dumps({
        "openapi": "3.0.0", "servers": [{"url": "/api/v1"}],
        "paths": {"/users/{id}": {
            "parameters": [{"name": "id", "in": "path"}],
            "get": {"parameters": [{"name": "expand", "in": "query"}]},
        }},
    })
    eps = parse_openapi(v3)
    assert {"path": "/api/v1/users/{id}", "method": "GET", "params": ["expand", "id"]} in eps

    v2 = json.dumps({"swagger": "2.0", "basePath": "/v2",
                     "paths": {"/pet": {"get": {"parameters": [{"name": "status"}]}}}})
    assert parse_openapi(v2) == [{"path": "/v2/pet", "method": "GET", "params": ["status"]}]


def test_parse_openapi_rejects_non_spec():
    assert parse_openapi('{"hello": 1}') is None        # no openapi/swagger marker
    assert parse_openapi("not json") is None
    assert parse_openapi('{"openapi":"3.0"}') is None    # marker but no paths


def test_graphql_detection_and_body_strip():
    assert looks_like_graphql('{"errors":[{"message":"Must provide query string"}]}', 400)
    assert looks_like_graphql('{"data":{"__schema":{}}}', 200)
    assert not looks_like_graphql("<html>not graphql</html>", 200)
    assert extract_http_body("HTTP/1.1 200 OK\r\nX: y\r\n\r\n{\"a\":1}") == '{"a":1}'


# --- module ----------------------------------------------------------------
class FakeTools:
    def __init__(self, missing=()):
        self.missing = set(missing)

    def resolve(self, name):
        if name in self.missing:
            raise ToolNotFoundError(f"{name} not found")
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "1.9.0"


class FakeExecutor:
    def __init__(self, stdout):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append((argv, input_text))
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
                               stdout=self.stdout, duration_s=0.1)


def _ctx(store, tmp_path, executor, tools, pipeline=None):
    return Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"], in_scope=["*.example.com"]),
        config=Config(pipeline=pipeline or {}), executor=executor, tools=tools,
        repository=store, results_dir=tmp_path,
    )


def _store_with_host(host="https://a.example.com"):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    return store, db


def test_api_discovery_parses_spec_emits_endpoints_and_finding(tmp_path):
    store, _ = _store_with_host()
    spec = json.dumps({"openapi": "3.0.0",
                       "paths": {"/users": {"get": {"parameters": [{"name": "page"}]}}}})
    # httpx -irr line for the openapi.json probe (response = headers + body)
    line = json.dumps({
        "input": "https://a.example.com/openapi.json",
        "url": "https://a.example.com/openapi.json",
        "status_code": 200,
        "response": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + spec,
    })
    ex = FakeExecutor(line)
    ctx = _ctx(store, tmp_path, ex, FakeTools())
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
    ]))

    result = ApiDiscovery().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    urls = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "url")}
    assert "https://a.example.com/openapi.json" in urls           # the spec itself
    assert "https://a.example.com/users?page=1" in urls           # parsed endpoint (param baked)
    findings = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "exposed_api_spec"]
    assert findings
    # results files written
    assert "openapi" in (tmp_path / "api.txt").read_text()
    assert json.loads((tmp_path / "api.json").read_text())["endpoints"]
    store.close()


def test_api_discovery_flags_graphql(tmp_path):
    store, _ = _store_with_host()
    line = json.dumps({
        "input": "https://a.example.com/graphql",
        "url": "https://a.example.com/graphql",
        "status_code": 400,
        "response": "HTTP/1.1 400 Bad Request\r\n\r\n{\"errors\":[{\"message\":\"Must provide query string\"}]}",
    })
    ex = FakeExecutor(line)
    ctx = _ctx(store, tmp_path, ex, FakeTools())
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
    ]))

    ApiDiscovery().run(ctx)

    findings = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "graphql_endpoint"]
    assert findings
    urls = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "url")}
    assert "https://a.example.com/graphql" in urls
    store.close()


def test_api_discovery_probes_known_paths(tmp_path):
    store, _ = _store_with_host()
    ex = FakeExecutor("")   # no responses matched
    ctx = _ctx(store, tmp_path, ex, FakeTools())
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
    ]))

    ApiDiscovery().run(ctx)

    fed = ex.calls[0][1]   # stdin URLs
    assert "https://a.example.com/openapi.json" in fed
    assert "https://a.example.com/graphql" in fed
    store.close()


def test_api_discovery_skips_when_httpx_missing(tmp_path):
    store, _ = _store_with_host()
    ctx = _ctx(store, tmp_path, FakeExecutor(""), FakeTools(missing={"httpx"}))
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
    ]))

    result = ApiDiscovery().run(ctx)
    assert result.status == ModuleStatus.SKIPPED
    store.close()
