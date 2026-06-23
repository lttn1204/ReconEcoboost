"""feroxbuster results carry status+size into the DB, and catch-alls are flagged."""

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


def _ferox_line(url, status, length, words=1, method="GET"):
    return json.dumps({
        "type": "response", "url": url, "path": "/x", "status": status,
        "method": method, "content_length": length, "word_count": words,
        "line_count": 1, "headers": {},
    })


def _ferox_json():
    # 11 catch-all hits (same size) + 1 genuine-looking hit (different size)
    lines = [_ferox_line(f"https://a.example.com/p{i}", 200, 1234, 10) for i in range(11)]
    lines.append(_ferox_line("https://a.example.com/realsecret", 200, 42, 3))
    return "\n".join(lines)


def _ctx_with_host():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(),
        executor=FakeExecutor(_ferox_json()),
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
        """feroxbuster tests all methods in ONE run and emits a line per method."""
        def __init__(self): self.calls = []
        def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
            self.calls.append(argv)
            out = "\n".join([
                _ferox_line("https://a.example.com/admin", 200, 100, 1, "GET"),
                _ferox_line("https://a.example.com/admin", 405, 0, 1, "POST"),
            ])
            return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS,
                                   exit_code=0, stdout=out, duration_s=0.0)

    db = Database(":memory:"); db.connect(); db.initialize()
    store = Store(db)
    ex = MethodExecutor()
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(pipeline={"dir_bruteforce": {"methods": ["GET", "POST"]}}),
        executor=ex, tools=Tools(), repository=store,
        results_dir=tmp_path,
    )
    store.start_run(ctx)
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("host", "https://a.example.com")])
    )

    DirBruteforce().run(ctx)

    # ONE feroxbuster run, both methods passed via -m
    assert len(ex.calls) == 1
    argv = ex.calls[0]
    assert "-m" in argv and "GET" in argv and "POST" in argv

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


def _command_argv(pipeline):
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(pipeline=pipeline),
    )
    tool = ToolHandle(name="feroxbuster", binary="feroxbuster", path="/usr/bin/feroxbuster")
    return DirBruteforce().commands(tool, "https://a.example.com", ctx)[0].argv


def test_recursion_flags_default_and_configurable():
    # default: recursion on at depth 1
    argv = _command_argv({})
    assert "-d" in argv and argv[argv.index("-d") + 1] == "1"
    assert "-n" not in argv
    assert "--dont-extract-links" in argv          # pure brute-force by default
    assert "-s" in argv                            # status allow-list passed

    # configurable depth + force-recursion
    argv = _command_argv({"dir_bruteforce": {"recursion": {"depth": 3, "force": True}}})
    assert argv[argv.index("-d") + 1] == "3"
    assert "--force-recursion" in argv


def test_recursion_can_be_disabled():
    argv = _command_argv({"dir_bruteforce": {"recursion": {"enabled": False}}})
    assert "-n" in argv and "-d" not in argv       # flat scan (no recursion)


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
