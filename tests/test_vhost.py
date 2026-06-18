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


def test_vhost_module_builds_full_hostnames_and_command():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = FakeExecutor(_ffuf_vhost_json())

    scope = Scope(targets=["example.com"], in_scope=["*.example.com"])
    ctx = Context(
        domain=Domain.WEB, scope=scope, config=Config(),
        executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)

    VhostDiscovery().run(ctx)

    # FUZZ keywords were reconstructed into full hostnames and persisted
    subs = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert subs == {"dev.example.com", "admin.example.com"}

    # the Host header was fuzzed for the target domain
    argv = ex.calls[0]
    assert "-H" in argv
    assert "Host: FUZZ.example.com" in argv
    assert "-ac" in argv  # auto-calibration on
    store.close()


def test_vhost_format_capture_is_readable():
    out = VhostDiscovery().format_capture(_ffuf_vhost_json())
    lines = [ln for ln in out.splitlines() if not ln.startswith("#")]
    assert any("dev" in ln and "200" in ln for ln in lines)
    assert '"results"' not in out  # not raw json
