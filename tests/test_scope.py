"""Tests for scope pattern matching and scope-gated fuzzing."""

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, Normalizer, ParsedRecord, ToolHandle
from reconecoboost.modules.web.dir_bruteforce import DirBruteforce
from reconecoboost.persistence import Database, Store


# --- pattern matching -------------------------------------------------------

def test_wildcard_matches_subdomains_not_apex():
    s = Scope(in_scope=["*.example.com"])
    assert s.is_allowed("a.example.com")
    assert s.is_allowed("x.y.example.com")
    assert not s.is_allowed("example.com")        # apex excluded by *.
    assert not s.is_allowed("evil.com")


def test_exact_matches_apex_only():
    s = Scope(in_scope=["example.com"])
    assert s.is_allowed("example.com")
    assert not s.is_allowed("a.example.com")       # subdomain not matched by exact


def test_apex_and_subdomains():
    s = Scope(in_scope=["example.com", "*.example.com"])
    assert s.is_allowed("example.com")
    assert s.is_allowed("a.example.com")
    assert not s.is_allowed("other.com")


def test_out_of_scope_wins():
    s = Scope(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert s.is_allowed("a.example.com")
    assert not s.is_allowed("admin.example.com")


def test_empty_in_scope_allows_all_not_excluded():
    s = Scope(out_of_scope=["*.internal.example.com"])
    assert s.is_allowed("anything.com")
    assert not s.is_allowed("db.internal.example.com")


def test_case_and_trailing_dot_normalized():
    s = Scope(in_scope=["*.Example.com"])
    assert s.is_allowed("A.EXAMPLE.COM.")


def test_seed_target_always_in_scope_even_with_wildcard():
    # the edge case: *.shop... excludes the host itself, but it's the target
    s = Scope(targets=["shop.example.com"], in_scope=["*.shop.example.com"])
    assert s.is_allowed("shop.example.com")       # target → always scanned
    assert s.is_allowed("a.shop.example.com")     # subdomain via wildcard
    assert not s.is_allowed("other.com")


def test_out_of_scope_beats_target():
    s = Scope(targets=["example.com"], out_of_scope=["example.com"])
    assert not s.is_allowed("example.com")


# --- scope-gated fuzzing ----------------------------------------------------

class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append(argv)
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0, stdout="{}", duration_s=0.0
        )


def test_seed_apex_is_injected_into_pipeline():
    """The seed target (apex) is scanned even though subfinder only returns subdomains."""
    from reconecoboost.modules.web.asset_discovery import AssetDiscovery

    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)

    class _Tools:
        def resolve(self, name):
            return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

        def version(self, name):
            return None

    class _Exec:
        def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
            return ExecutionResult(
                argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
                stdout="elearning.example.com\n", duration_s=0.0,
            )

    # apex + one specific subdomain in scope (both exact)
    scope = Scope(targets=["example.com"], in_scope=["example.com", "elearning.example.com"])
    ctx = Context(
        domain=Domain.WEB, scope=scope, config=Config(),
        executor=_Exec(), tools=_Tools(), repository=store,
    )
    store.start_run(ctx)

    AssetDiscovery().run(ctx)

    keys = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert "example.com" in keys           # seeded apex is present (was missing before)
    assert "elearning.example.com" in keys  # discovered + in scope
    store.close()


def test_dir_bruteforce_only_runs_on_in_scope_hosts():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = FakeExecutor()

    scope = Scope(targets=["example.com"], in_scope=["*.example.com"])
    ctx = Context(
        domain=Domain.WEB, scope=scope, config=Config(),
        executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)

    # Two alive hosts: one in scope, one not (e.g. a third-party CDN host).
    store.persist_normalization(
        ctx.run_id,
        Normalizer().normalize([
            ParsedRecord("host", "https://a.example.com"),
            ParsedRecord("host", "https://cdn.other.com"),
        ]),
    )

    DirBruteforce().run(ctx)

    # ffuf invoked exactly once — only for the in-scope host
    assert len(ex.calls) == 1
    fuzzed_url = ex.calls[0][ex.calls[0].index("-u") + 1]
    assert "a.example.com" in fuzzed_url
    assert "other.com" not in fuzzed_url
    store.close()
