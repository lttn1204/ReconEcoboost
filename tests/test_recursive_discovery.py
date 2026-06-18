"""Tests for recursive subdomain discovery with configurable depth."""

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, ToolHandle
from reconecoboost.modules.web.asset_discovery import AssetDiscovery
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class LevelExecutor:
    """subfinder fake: returns child subdomains based on the -d <domain> arg."""

    MAP = {
        "example.com": "a.example.com\n",
        "a.example.com": "b.a.example.com\n",
        "b.a.example.com": "",  # no more
    }

    def __init__(self):
        self.domains_scanned = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        domain = argv[argv.index("-d") + 1] if "-d" in argv else ""
        self.domains_scanned.append(domain)
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
            stdout=self.MAP.get(domain, ""), duration_s=0.0,
        )


def _run(depth):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = LevelExecutor()

    scope = Scope(targets=["example.com"], in_scope=["*.example.com"])
    ctx = Context(
        domain=Domain.WEB, scope=scope,
        config=Config(pipeline={"discovery": {"recursive_depth": depth}}),
        executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)
    AssetDiscovery().run(ctx)
    keys = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    return keys, ex.domains_scanned, store


def test_depth_1_no_recursion():
    keys, scanned, store = _run(depth=1)
    assert "a.example.com" in keys
    assert "b.a.example.com" not in keys     # not recursed into
    assert scanned == ["example.com"]        # only the seed scanned
    store.close()


def test_depth_2_one_level_of_recursion():
    keys, scanned, store = _run(depth=2)
    assert "a.example.com" in keys
    assert "b.a.example.com" in keys
    assert scanned == ["example.com", "a.example.com"]
    store.close()


def test_high_depth_runs_until_exhausted():
    keys, scanned, store = _run(depth=100)
    # discovers a -> b.a, then b.a yields nothing and it stops (no infinite loop)
    assert {"a.example.com", "b.a.example.com"} <= keys
    assert scanned == ["example.com", "a.example.com", "b.a.example.com"]
    store.close()
