"""Tests for the ffuf vhost-discovery module (a newly-added tool)."""

import json

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, ToolHandle
from reconecoboost.modules.web.parsers import FfufVhostParser
from reconecoboost.modules.web.vhost_discovery import VhostDiscovery
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    def __init__(self, stdout):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append(argv)
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
            stdout=self.stdout, duration_s=0.0,
        )


def _ffuf_vhost_json():
    return json.dumps({"results": [
        {"input": {"FUZZ": "dev"}, "status": 200, "length": 111, "words": 5},
        {"input": {"FUZZ": "admin"}, "status": 200, "length": 222, "words": 6},
    ]})


def test_vhost_parser_emits_fuzz_keywords():
    parsed = FfufVhostParser().parse(_ffuf_vhost_json())
    assert {p.key for p in parsed} == {"dev", "admin"}
    assert all(p.asset_type == "subdomain" for p in parsed)
    assert parsed[0].attributes.get("status") == 200


def test_vhost_registers_matches_as_live_hosts(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = FakeExecutor(_ffuf_vhost_json())

    scope = Scope(targets=["example.com"], in_scope=["*.example.com"])
    ctx = Context(
        domain=Domain.WEB, scope=scope, config=Config(),
        executor=ex, tools=FakeTools(), repository=store, results_dir=tmp_path,
    )
    store.start_run(ctx)

    VhostDiscovery().run(ctx)

    # matched vhosts registered directly as live HOSTS (origins), not subdomains
    hosts = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "host")}
    assert "https://dev.example.com" in hosts
    assert "https://admin.example.com" in hosts
    assert store.list_assets(ctx.run_id, "subdomain") == []  # no subdomain produced (avoids DAG cycle)

    # Host header fuzzed for the apex, auto-calibration on
    argv = ex.calls[0]
    assert "Host: FUZZ.example.com" in argv and "-ac" in argv
    # results summary written
    assert "dev.example.com" in (tmp_path / "vhost.txt").read_text()
    store.close()


def test_vhost_fuzzes_dnsx_ips_and_skips_internal(tmp_path):
    from reconecoboost.engine import Normalizer, ParsedRecord

    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = FakeExecutor(_ffuf_vhost_json())
    scope = Scope(targets=["example.com"], in_scope=["*.example.com"])
    ctx = Context(
        domain=Domain.WEB, scope=scope,
        config=Config(pipeline={"vhost_discovery": {"schemes": ["https"]}}),
        executor=ex, tools=FakeTools(), repository=store, results_dir=tmp_path,
    )
    store.start_run(ctx)
    # dnsx-enriched subdomains: one public IP, one internal
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", "a.example.com", attributes={"resolved": True, "ip": ["1.2.3.4"]}, tool="dnsx"),
        ParsedRecord("subdomain", "b.example.com", attributes={"internal": True, "ip": ["10.0.0.9"]}, tool="dnsx"),
    ]))

    VhostDiscovery().run(ctx)

    fuzzed = " ".join(" ".join(c) for c in ex.calls)
    assert "https://1.2.3.4/" in fuzzed      # public IP fuzzed
    assert "10.0.0.9" not in fuzzed          # internal IP skipped
    store.close()
