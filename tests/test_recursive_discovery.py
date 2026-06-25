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


# asset_discovery is PASSIVE (subfinder) and intentionally NON-recursive: re-running
# subfinder on every found subdomain yields ~nothing new but multiplies runs
# explosively (a depth-3 run on a big org hung the pipeline before validation).
# Recursive sub-of-sub discovery is the job of ACTIVE brute (dns_resolve), tested in
# test_dns_resolve.py, and the bounded discovery loop.
def test_asset_discovery_scans_only_the_seed_at_depth_1():
    keys, scanned, store = _run(depth=1)
    assert "a.example.com" in keys
    assert "b.a.example.com" not in keys
    assert scanned == ["example.com"]
    store.close()


def test_asset_discovery_does_not_recurse_even_at_high_depth():
    # depth is ignored by passive enumeration — only the seed is ever scanned.
    keys, scanned, store = _run(depth=100)
    assert "a.example.com" in keys
    assert "b.a.example.com" not in keys     # NOT recursed despite depth 100
    assert scanned == ["example.com"]        # subfinder ran exactly once (no explosion)
    store.close()
