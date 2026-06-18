"""Tests for config-driven per-tool request rate limiting."""

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import (
    ExecutionResult,
    ExecutionStatus,
    Normalizer,
    ParsedRecord,
    ToolHandle,
)
from reconecoboost.modules.web.alive_detection import AliveDetection
from reconecoboost.modules.web.asset_discovery import AssetDiscovery
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append(argv)
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
            stdout=self.stdout, duration_s=0.0,
        )


def _store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def _ctx(executor, store, tools_config):
    config = Config(tools=tools_config)
    return Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=config,
        executor=executor,
        tools=FakeTools(),
        repository=store,
    )


def test_rate_flag_injected_from_default():
    store = _store()
    ex = FakeExecutor()
    tools_config = {"defaults": {"rate_limit": 50}, "tools": {"httpx": {"rate_flag": "-rl"}}}
    ctx = _ctx(ex, store, tools_config)
    store.start_run(ctx)
    # alive_detection reads subdomains from the store — seed one
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("subdomain", "a.example.com")])
    )

    AliveDetection().run(ctx)

    assert ex.calls, "httpx should have been invoked"
    argv = ex.calls[-1]
    assert "-rl" in argv
    assert argv[argv.index("-rl") + 1] == "50"
    store.close()


def test_per_tool_rate_overrides_default():
    store = _store()
    ex = FakeExecutor("a.example.com\n")
    tools_config = {
        "defaults": {"rate_limit": 50},
        "tools": {"subfinder": {"rate_flag": "-rl", "rate_limit": 10}},
    }
    ctx = _ctx(ex, store, tools_config)
    store.start_run(ctx)

    AssetDiscovery().run(ctx)

    argv = ex.calls[-1]
    assert "-rl" in argv
    assert argv[argv.index("-rl") + 1] == "10"  # per-tool wins over default 50
    store.close()


def test_no_rate_flag_means_no_injection():
    store = _store()
    ex = FakeExecutor("a.example.com\n")
    # subfinder has no rate_flag here, even though a default rate exists
    tools_config = {"defaults": {"rate_limit": 50}, "tools": {"subfinder": {}}}
    ctx = _ctx(ex, store, tools_config)
    store.start_run(ctx)

    AssetDiscovery().run(ctx)

    assert "-rl" not in ex.calls[-1]
    assert "50" not in ex.calls[-1]
    store.close()


def test_zero_rate_is_unlimited():
    store = _store()
    ex = FakeExecutor("a.example.com\n")
    tools_config = {"tools": {"subfinder": {"rate_flag": "-rl", "rate_limit": 0}}}
    ctx = _ctx(ex, store, tools_config)
    store.start_run(ctx)

    AssetDiscovery().run(ctx)

    assert "-rl" not in ex.calls[-1]
    store.close()
