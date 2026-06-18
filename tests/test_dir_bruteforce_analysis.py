"""ffuf results carry status+size into the DB, and catch-alls are flagged."""

import json

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, Normalizer, ParsedRecord, ToolHandle
from reconecoboost.modules.web.dir_bruteforce import DirBruteforce
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    def __init__(self, stdout):
        self.stdout = stdout

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
            stdout=self.stdout, duration_s=0.0,
        )


def _ffuf_json():
    # 11 catch-all hits (same size) + 1 genuine-looking hit (different size)
    results = [
        {"url": f"https://a.example.com/p{i}", "status": 200, "length": 1234, "words": 10, "lines": 5}
        for i in range(11)
    ]
    results.append(
        {"url": "https://a.example.com/realsecret", "status": 200, "length": 42, "words": 3, "lines": 1}
    )
    return json.dumps({"results": results})


def _ctx_with_host():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(),
        executor=FakeExecutor(_ffuf_json()),
        tools=FakeTools(),
        repository=store,
    )
    store.start_run(ctx)
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("host", "https://a.example.com")])
    )
    return ctx, store


def test_status_and_size_saved_to_db():
    ctx, store = _ctx_with_host()
    DirBruteforce().run(ctx)

    urls = store.list_assets(ctx.run_id, "url")
    assert len(urls) == 12
    for u in urls:
        attrs = json.loads(u["attributes_json"])
        # per-method results: {"methods": {"GET": {"status":..., "length":...}}}
        get = attrs["methods"]["GET"]
        assert "status" in get
        assert "length" in get  # response size
    store.close()


def test_multiple_methods_folded_per_url(tmp_path):
    """With methods [GET, POST], each URL stores per-method status/size, and a
    single consolidated file per host is written (not one per method)."""
    from reconecoboost.config.loader import Config
    from reconecoboost.core.context import Context
    from reconecoboost.core.models import Domain
    from reconecoboost.core.scope import Scope
    from reconecoboost.engine import Normalizer, ParsedRecord, ToolHandle
    from reconecoboost.graph import SqliteKnowledgeGraph  # noqa: F401

    class Tools:
        def resolve(self, name): return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")
        def version(self, name): return None

    class MethodExecutor:
        """Returns ffuf json whose config.method reflects the -X arg."""
        def __init__(self): self.calls = []
        def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
            self.calls.append(argv)
            method = argv[argv.index("-X") + 1] if "-X" in argv else "GET"
            status, length = (200, 100) if method == "GET" else (405, 0)
            return ExecutionResult(
                argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
                stdout=json.dumps({
                    "config": {"method": method},
                    "results": [{"url": "https://a.example.com/admin",
                                 "status": status, "length": length, "words": 1}],
                }),
                duration_s=0.0,
            )

    db = Database(":memory:"); db.connect(); db.initialize()
    store = Store(db)
    ex = MethodExecutor()
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(tools={"tools": {"ffuf": {"methods": ["GET", "POST"]}}}),
        executor=ex, tools=Tools(), repository=store,
        results_dir=tmp_path,
    )
    store.start_run(ctx)
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("host", "https://a.example.com")])
    )

    DirBruteforce().run(ctx)

    # two ffuf passes (one per method), one for each -X
    methods_run = {c[c.index("-X") + 1] for c in ex.calls if "-X" in c}
    assert methods_run == {"GET", "POST"}

    # one url asset, with both methods folded in
    urls = store.list_assets(ctx.run_id, "url")
    assert len(urls) == 1
    methods = json.loads(urls[0]["attributes_json"])["methods"]
    assert methods["GET"]["status"] == 200
    assert methods["POST"]["status"] == 405

    # ONE consolidated file for the host (not one per method), with both methods
    files = list(tmp_path.glob("dir_bruteforce-*.txt"))
    assert len(files) == 1
    text = files[0].read_text()
    assert "GET" in text and "POST" in text
    assert "https://a.example.com/admin" in text
    store.close()


def test_ffuf_parser_isolates_json_from_mixed_stdout():
    """ffuf -s writes matched keywords before the -o /dev/stdout JSON — the
    parser must isolate the JSON object despite the leading keyword lines."""
    from reconecoboost.modules.web.parsers import FfufParser

    mixed = (
        "admin\nlogin\nphpinfo.php\n"  # ffuf -s keyword lines
        + json.dumps({
            "config": {"method": "GET"},
            "results": [
                {"url": "https://x/admin", "status": 302, "length": 167, "words": 6},
                {"url": "https://x/phpinfo.php", "status": 200, "length": 246, "words": 17},
            ],
        })
    )
    parsed = FfufParser().parse(mixed)
    assert {p.key for p in parsed} == {"https://x/admin", "https://x/phpinfo.php"}
    assert any(p.attributes.get("status") == 200 for p in parsed)
    assert all(p.attributes.get("method") == "GET" for p in parsed)


def test_catch_all_flagged_as_finding():
    ctx, store = _ctx_with_host()
    DirBruteforce().run(ctx)

    findings = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "recon_note"]
    assert len(findings) == 1
    detail = json.loads(findings[0]["detail_json"])
    assert detail["shared_size"] == 1234
    assert detail["shared_count"] == 11
    assert detail["total_results"] == 12
    store.close()
