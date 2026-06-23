"""Tests for Phase 2 param discovery: JS/URL mining, arjun parsing, the module."""

import json

from reconecoboost.analysis.params import mine_js_params, query_param_names
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.errors import ToolNotFoundError
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import (
    ExecutionResult,
    ExecutionStatus,
    Normalizer,
    ParsedRecord,
    ToolHandle,
)
from reconecoboost.modules.web.param_discovery import ParamDiscovery
from reconecoboost.modules.web.parsers import ArjunParser, bake_params
from reconecoboost.persistence import Database, Store


# --- pure mining -----------------------------------------------------------
def test_mine_js_params_extracts_url_and_http_object_params():
    js = """
    this.http.get('/cp/api/account?format=json&lang=vi&accountId=5');
    fetch("https://h/api/transfer?beneficiaryId=1");
    axios.get(url, { params: { txnAmount: a, otpCode: b } });
    // ternary must NOT be mined as a query param:
    var x = cond ? B.isScrolling = 1 : c;
    const _buffer = new Uint8Array(); let AUTO_MODE = 2;
    """
    found = mine_js_params(js)
    # real params surface (from quoted URLs + http object literal)
    for p in ("format", "lang", "accountId", "beneficiaryId", "txnAmount", "otpCode"):
        assert p in found, p
    # minified-bundle noise must NOT appear
    for noise in ("B.isScrolling", "_buffer", "AUTO_MODE", "cond", "x"):
        assert noise not in found, noise


def test_query_param_names_keeps_real_params_drops_noise():
    assert query_param_names("https://h/api?id=1&page=2&q=a") == {"id", "page", "q"}
    assert query_param_names("https://h/api") == set()
    # all-digit and long-hex (hash) "names" are not real params
    got = query_param_names("https://h/x?23391439=1&50db0456fde2a241f005968eede3f987=2&ok=3")
    assert got == {"ok"}


# --- arjun parser ----------------------------------------------------------
def test_bake_params_uses_placeholder_value():
    # blank values are dropped by parse_qs, so triage wouldn't see them
    assert bake_params("https://h/a", ["id", "debug"]) == "https://h/a?id=1&debug=1"
    assert bake_params("https://h/a?x=1", ["id"]) == "https://h/a?x=1&id=1"
    assert bake_params("https://h/a", []) == "https://h/a"


def test_arjun_parser_bakes_params_and_triage_sees_them():
    raw = json.dumps({
        # "id" is a known gf-pattern vuln-class param; "accountId" is app-specific
        "https://h/cp/api/transfer": {"method": "GET", "params": ["id", "accountId"]},
        "https://h/empty": {"method": "GET", "params": []},  # skipped
    })
    recs = ArjunParser().parse(raw)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.attributes["discovered_params"] == ["id", "accountId"]
    assert rec.attributes["param_method"] == "GET"

    # triage's param scoring must pick the baked params up
    from reconecoboost.analysis.triage import param_keys, param_vuln_classes
    keys = param_keys(rec.key)
    assert {"id", "accountId"} <= keys           # both visible despite placeholder values
    assert param_vuln_classes(keys)              # "id" tags a vuln class (sqli/idor)


# --- module helpers --------------------------------------------------------
class FakeTools:
    def __init__(self, missing=()):
        self.missing = set(missing)

    def resolve(self, name):
        if name in self.missing:
            raise ToolNotFoundError(f"{name} not found")
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "2.2.7"


class ArjunFakeExecutor:
    """Simulates arjun: writes a JSON result file to the -oJ path in argv."""

    def __init__(self, result_map):
        self.result_map = result_map
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append(argv)
        if "-oJ" in argv:
            out = argv[argv.index("-oJ") + 1]
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(self.result_map, fh)
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS,
                               exit_code=0, stdout="", duration_s=0.1)


def _store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def _ctx(store, tmp_path, executor, tools, pipeline=None):
    return Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"], in_scope=["*.example.com"]),
        config=Config(pipeline=pipeline or {}), executor=executor, tools=tools,
        repository=store, results_dir=tmp_path,
    )


def test_gather_inputs_live_dedupe_static_and_cap(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, ArjunFakeExecutor({}), FakeTools(),
               {"param_discovery": {"max_urls": 10}})
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/api/user", attributes={"status_code": 200}, tool="t"),
        ParsedRecord("url", "https://a.example.com/api/user?x=1", attributes={"status_code": 200}, tool="t"),  # dup path
        ParsedRecord("url", "https://a.example.com/app.js", attributes={"status_code": 200}, tool="t"),       # static
        ParsedRecord("url", "https://a.example.com/dead", attributes={"status_code": 404}, tool="t"),         # not live
        ParsedRecord("url", "https://a.example.com/admin", attributes={"status_code": 403}, tool="t"),        # live-ish
    ]))

    inputs = ParamDiscovery()._gather_inputs(ctx)

    assert "https://a.example.com/api/user" in inputs
    assert "https://a.example.com/admin" in inputs   # 403 counts as responding
    assert "https://a.example.com/app.js" not in inputs       # static skipped
    assert "https://a.example.com/dead" not in inputs         # 404 not live
    # de-duped by path: only one /api/user entry
    assert sum(1 for i in inputs if i.endswith("/api/user")) == 1


def test_gather_inputs_drops_crawler_artifacts(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, ArjunFakeExecutor({}), FakeTools())
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/api/ok", attributes={"status_code": 200}, tool="t"),
        ParsedRecord("url", "https://a.example.com/'+url+'", attributes={"status_code": 200}, tool="t"),
        ParsedRecord("url", "https://a.example.com/').concat(x", attributes={"status_code": 200}, tool="t"),
    ]))

    inputs = ParamDiscovery()._gather_inputs(ctx)
    assert inputs == ["https://a.example.com/api/ok"]   # JS-template junk dropped


def test_hard_fail_when_engine_missing(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, ArjunFakeExecutor({}), FakeTools(missing={"arjun"}))
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/api", attributes={"status_code": 200}, tool="t"),
    ]))

    result = ParamDiscovery().run(ctx)
    assert result.status == ModuleStatus.FAILED


def test_end_to_end_validates_persists_and_writes_results(tmp_path):
    store = _store()
    arjun_out = {"https://a.example.com/api/transfer": {"method": "GET",
                                                        "params": ["accountId", "debug"]}}
    ex = ArjunFakeExecutor(arjun_out)
    ctx = _ctx(store, tmp_path, ex, FakeTools(),
               {"param_discovery": {"wordlist": str(tmp_path / "base.txt")}})
    (tmp_path / "base.txt").write_text("id\npage\n", encoding="utf-8")
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/api/transfer", attributes={"status_code": 200}, tool="t"),
    ]))

    result = ParamDiscovery().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert result.meta["with_params"] == 1
    # baked URL persisted as a url asset
    urls = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "url")}
    assert "https://a.example.com/api/transfer?accountId=1&debug=1" in urls
    # results files written
    params_txt = (tmp_path / "params.txt").read_text()
    assert "accountId, debug" in params_txt
    pj = json.loads((tmp_path / "params.json").read_text())
    assert pj[0]["params"] == ["accountId", "debug"]
    # arjun was invoked with our merged wordlist + targets
    argv = ex.calls[0]
    assert "-w" in argv and "-i" in argv and "-m" in argv
    store.close()


def test_ai_params_seam_folds_into_wordlist(tmp_path):
    store = _store()
    (tmp_path / "ai_params.txt").write_text("vneid\nsoTaiKhoan\n", encoding="utf-8")
    (tmp_path / "base.txt").write_text("id\n", encoding="utf-8")
    ex = ArjunFakeExecutor({})
    ctx = _ctx(store, tmp_path, ex, FakeTools(),
               {"param_discovery": {"wordlist": str(tmp_path / "base.txt")}})
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("url", "https://a.example.com/api", attributes={"status_code": 200}, tool="t"),
    ]))

    ParamDiscovery().run(ctx)

    merged = (tmp_path / "param_wordlist.txt").read_text().split()
    assert "vneid" in merged and "soTaiKhoan" in merged   # AI seam folded in
    assert "id" in merged                                  # base kept
