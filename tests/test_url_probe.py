"""Tests for url_probe: httpx over discovered URLs records their status."""

import json

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, Normalizer, ParsedRecord, ToolHandle
from reconecoboost.modules.web.parsers import HttpxUrlParser
from reconecoboost.modules.web.url_probe import UrlProbe
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return None


class FakeExecutor:
    """httpx fake: returns a json line (with status) only for URLs that 'respond'."""

    LIVE = {"https://a.example.com/login": 200, "https://a.example.com/admin": 403}

    def __init__(self):
        self.input_text = None

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.input_text = input_text
        lines = []
        for url in (input_text or "").splitlines():
            url = url.strip()
            if url in self.LIVE:
                lines.append(json.dumps({"input": url, "url": url, "status_code": self.LIVE[url]}))
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
            stdout="\n".join(lines), duration_s=0.0,
        )


def test_httpx_url_parser_keys_by_input_with_status():
    raw = json.dumps({"input": "https://x/p", "url": "https://x/p", "status_code": 200, "content_length": 12})
    recs = HttpxUrlParser().parse(raw)
    assert recs[0].asset_type == "url"
    assert recs[0].key == "https://x/p"
    assert recs[0].attributes["status_code"] == 200


def test_url_probe_records_status_on_existing_url_assets():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ex = FakeExecutor()
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)
    # discovered URLs (from katana/gau/ffuf) — no status yet
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/login", tool="katana"),
        ParsedRecord("url", "https://a.example.com/admin", tool="ffuf"),
        ParsedRecord("url", "https://a.example.com/ghost", tool="gau"),  # dead
    ]))

    UrlProbe().run(ctx)

    by_key = {a["canonical_key"]: json.loads(a["attributes_json"]) for a in store.list_assets(ctx.run_id, "url")}
    assert by_key["https://a.example.com/login"]["status_code"] == 200
    assert by_key["https://a.example.com/admin"]["status_code"] == 403
    assert "status_code" not in by_key["https://a.example.com/ghost"]  # never responded
    store.close()
