"""Tests for the shared js_fetch stage (selection + single fetch + body cache)."""

import json

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, Normalizer, ParsedRecord, ToolHandle
from reconecoboost.modules.web.js_fetch import JsFetch, load_bodies
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "1.0"


class FakeExecutor:
    def __init__(self, stdout):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append((argv, input_text))
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
                               stdout=self.stdout, duration_s=0.1)


def _store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def test_js_fetch_selection_and_body_cache(tmp_path):
    store = _store()
    body = 'const t="x";'
    stdout = "\n".join([
        json.dumps({"url": "https://a.example.com/app.js", "response": body}),
        json.dumps({"url": "https://a.example.com/dashboard", "response": "<html>secret</html>"}),
    ])
    ex = FakeExecutor(stdout)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), executor=ex, tools=FakeTools(), repository=store, results_dir=tmp_path,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/app.js", tool="katana"),            # ext
        ParsedRecord("url", "https://a.example.com/dashboard", attributes={"status_code": 200}, tool="url_probe"),  # live 200
        ParsedRecord("url", "https://a.example.com/old", attributes={"status_code": 404}, tool="gau"),               # dead
        ParsedRecord("url", "https://a.example.com/logo.png", attributes={"status_code": 200}, tool="url_probe"),    # media
    ]))

    result = JsFetch().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    fed = set(ex.calls[0][1].split())
    assert fed == {"https://a.example.com/app.js", "https://a.example.com/dashboard"}
    # bodies cached and re-readable by downstream modules
    bodies = dict(load_bodies(tmp_path))
    assert bodies["https://a.example.com/app.js"] == body
    assert (tmp_path / "responses" / "index.json").exists()
    store.close()


def test_js_fetch_disabled(tmp_path):
    store = _store()
    ex = FakeExecutor("")
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(pipeline={"js_fetch": {"enabled": False}}),
        executor=ex, tools=FakeTools(), repository=store, results_dir=tmp_path,
    )
    store.start_run(ctx)
    result = JsFetch().run(ctx)
    assert result.meta == {"disabled": True}
    assert ex.calls == []
    store.close()
