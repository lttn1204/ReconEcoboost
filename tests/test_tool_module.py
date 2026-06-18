"""Tests for the ToolModule flow: execute -> parse -> scope-filter -> persist."""

from datetime import datetime, timezone

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, ToolHandle
from reconecoboost.modules.web.asset_discovery import AssetDiscovery
from reconecoboost.persistence import Database, Store


class FakeTools:
    """Stand-in ToolManager that always resolves and reports no version."""

    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    """Returns canned stdout regardless of argv (records the calls)."""

    def __init__(self, stdout):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append(argv)
        return ExecutionResult(
            argv=argv,
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            stdout=self.stdout,
            duration_s=0.01,
        )


def _make_ctx(executor, store, scope):
    return Context(
        domain=Domain.WEB,
        scope=scope,
        config=Config(),
        executor=executor,
        tools=FakeTools(),
        repository=store,
    )


def _open_store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def test_asset_discovery_persists_subdomains():
    store = _open_store()
    executor = FakeExecutor("a.example.com\nb.example.com\n")
    ctx = _make_ctx(executor, store, Scope(targets=["example.com"]))
    store.start_run(ctx)

    result = AssetDiscovery().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    keys = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    # subfinder results PLUS the seeded target (so the apex is scanned too)
    assert keys == {"a.example.com", "b.example.com", "example.com"}
    # tool_run was recorded
    assert len(store.list_tool_runs(ctx.run_id)) == 1
    store.close()


def test_scope_filters_out_of_scope_results():
    store = _open_store()
    executor = FakeExecutor("a.example.com\nevil.com\n")
    scope = Scope(targets=["example.com"], in_scope=["*.example.com"])
    ctx = _make_ctx(executor, store, scope)
    store.start_run(ctx)

    AssetDiscovery().run(ctx)

    keys = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    # a.example.com via wildcard, example.com because it's the target; evil.com dropped
    assert "evil.com" not in keys
    assert {"a.example.com", "example.com"} <= keys
    store.close()


def test_missing_tool_skips_gracefully():
    store = _open_store()

    class MissingTools:
        def resolve(self, name):
            from reconecoboost.core.errors import ToolNotFoundError
            raise ToolNotFoundError(name)

        def version(self, name):
            return None

    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(),
        executor=FakeExecutor(""),
        tools=MissingTools(),
        repository=store,
    )
    store.start_run(ctx)

    result = AssetDiscovery().run(ctx)
    assert result.status == ModuleStatus.SKIPPED
    store.close()
