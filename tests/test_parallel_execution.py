"""ToolModule runs distinct hosts in parallel (per-host rate preserved, DB on main)."""

import threading
import time

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.entities import Relation
from reconecoboost.core.models import Domain, Stage
from reconecoboost.core.scope import Scope
from reconecoboost.engine import PARSERS, Normalizer, ParsedRecord
from reconecoboost.engine.executor import ExecutionResult, ExecutionStatus
from reconecoboost.graph import SqliteKnowledgeGraph
from reconecoboost.modules.base import ToolInvocation, ToolModule
from reconecoboost.persistence import Database, Store


class _SlowExecutor:
    """Each run() sleeps, records its thread id, and echoes the target host."""

    def __init__(self, delay=0.2):
        self.delay = delay
        self.threads: set[int] = set()

    def run(self, argv, timeout_s=None, input_text=None):
        self.threads.add(threading.get_ident())
        time.sleep(self.delay)
        host = argv[argv.index("-u") + 1]
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS,
                               exit_code=0, stdout=host, duration_s=self.delay)


class _EchoParser:
    tool = "dummy"

    def parse(self, stdout):
        host = stdout.strip()   # already scheme://host (the input asset key)
        url = f"{host}/found"
        return [ParsedRecord(
            "url", url, tool="dummy",
            relations=[Relation("url", url, "belongs_to", "host", host)])]


class _FakeTools:
    def resolve(self, name): return name
    def version(self, name): return "1.0"


class _DummyModule(ToolModule):
    name = "dummy_mod"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    tool = "dummy"
    parser = "dummy"
    input_type = "host"

    def command(self, tool, item, ctx):
        return ToolInvocation(argv=["dummytool", "-u", item])


def _seed_ctx(concurrency, hosts, delay=0.2):
    if not PARSERS.has("dummy"):
        PARSERS.register(_EchoParser())
    db = Database(":memory:")
    db.connect(); db.initialize()
    store = Store(db)
    cfg = Config()
    cfg.pipeline = {"max_concurrent_targets": concurrency}
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=hosts), config=cfg,
        repository=store, graph=SqliteKnowledgeGraph(db),
        executor=_SlowExecutor(delay), tools=_FakeTools(),
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize(
        [ParsedRecord("host", f"https://{h}", attributes={"status_code": 200},
                      tool="httpx") for h in hosts]))
    return ctx, store


HOSTS = [f"h{i}.example.com" for i in range(5)]


def test_parallel_across_hosts_is_faster_and_uses_threads():
    ctx, store = _seed_ctx(concurrency=5, hosts=HOSTS, delay=0.2)
    start = time.monotonic()
    result = _DummyModule().run(ctx)
    elapsed = time.monotonic() - start

    assert result.status.value == "success"
    # 5 hosts x 0.2s serial = 1.0s; parallel should be well under that
    assert elapsed < 0.6, f"not parallel: {elapsed:.2f}s"
    assert len(ctx.executor.threads) > 1  # multiple worker threads used
    # every host produced its url asset (DB writes happened on the main thread, no error)
    urls = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "url")}
    assert urls == {f"https://{h}/found" for h in HOSTS}
    assert len(store.list_tool_runs(ctx.run_id)) == 5
    store.close()


def test_serial_when_concurrency_one():
    ctx, store = _seed_ctx(concurrency=1, hosts=HOSTS, delay=0.05)
    _DummyModule().run(ctx)
    assert len(ctx.executor.threads) == 1  # all on the caller thread
    urls = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "url")}
    assert urls == {f"https://{h}/found" for h in HOSTS}
    store.close()
