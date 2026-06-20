"""Tests for the curated AI context (Step 2) + URL host-case normalization."""

from reconecoboost.analysis.web import _curated_payload
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.entities import Relation, canonical_key
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.graph import SqliteKnowledgeGraph
from reconecoboost.modules.web.triage import Triage
from reconecoboost.persistence import Database, Store


# --- host-case normalization (pre-task) -----------------------------------
def test_url_host_lowercased_path_preserved():
    assert canonical_key("url", "https://Google.Com/tesT") == "https://google.com/tesT"
    assert canonical_key("url", "HTTPS://A.Example.COM/x?Q=1") == "https://a.example.com/x?Q=1"
    # relative / non-URL values untouched
    assert canonical_key("url", "/just/a/path") == "/just/a/path"


# --- curated context ------------------------------------------------------
def _ctx(ai_cfg: dict, *, run_triage: bool = True):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(ai=ai_cfg), repository=store, graph=SqliteKnowledgeGraph(db),
    )
    store.start_run(ctx)
    records = [
        ParsedRecord("host", "https://a.example.com",
                     attributes={"status_code": 200, "tech": ["DNN"]}, tool="httpx"),
        ParsedRecord(
            "url", "https://a.example.com/api/upload",
            attributes={"methods": {"GET": {"status": 403, "length": 0},
                                    "POST": {"status": 200, "length": 9}}},
            tool="ffuf",
            relations=[Relation("url", "https://a.example.com/api/upload",
                                "belongs_to", "host", "https://a.example.com")],
        ),
        *[ParsedRecord("url", f"https://a.example.com/n{i}",
                       attributes={"status_code": 200}, tool="gau") for i in range(5)],
    ]
    store.persist_normalization(ctx.run_id, Normalizer().normalize(records))
    if run_triage:
        Triage().run(ctx)
    return ctx, store


def test_curated_includes_guaranteed_lead_and_annotates():
    # top_n=1 would normally surface only the single highest scorer...
    ctx, store = _ctx({"context": "curated", "context_top_n": 1, "context_max_nodes": 60})
    payload = _curated_payload(ctx)
    keys = {n["key"] for n in payload["nodes"]}

    # ...but the POST method-anomaly URL is guaranteed in regardless of top_n
    assert "https://a.example.com/api/upload" in keys
    # its host comes in as a 1-hop neighbor
    assert "https://a.example.com" in keys
    # neutral (score-0) URLs are excluded from the curated context
    assert not any(k.endswith("/n0") for k in keys)
    # nodes are annotated with the deterministic triage signal
    upload = next(n for n in payload["nodes"] if n["key"].endswith("/api/upload"))
    assert "method-anomaly" in upload["attributes"]["_triage"]["tags"]
    store.close()


def test_context_max_nodes_caps_payload_keeping_guaranteed():
    ctx, store = _ctx({"context": "curated", "context_top_n": 25, "context_max_nodes": 1})
    payload = _curated_payload(ctx)
    assert len(payload["nodes"]) <= 1
    assert payload["nodes"][0]["key"] == "https://a.example.com/api/upload"  # guaranteed kept
    store.close()


def _multi_host_ctx(ai_cfg: dict):
    """Two subdomains, one noisy — to exercise per-host fairness."""
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(ai=ai_cfg), repository=store, graph=SqliteKnowledgeGraph(db),
    )
    store.start_run(ctx)
    records = [
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
        ParsedRecord("host", "https://b.example.com", attributes={"status_code": 200}, tool="httpx"),
    ]
    # a.example.com is "noisy": several interesting-path URLs
    for path in ("admin", "login", "dashboard", "upload"):
        records.append(ParsedRecord(
            "url", f"https://a.example.com/{path}", attributes={"status_code": 200}, tool="katana",
            relations=[Relation("url", f"https://a.example.com/{path}", "belongs_to", "host", "https://a.example.com")]))
    # b.example.com is "quiet": a single interesting URL
    records.append(ParsedRecord(
        "url", "https://b.example.com/api", attributes={"status_code": 200}, tool="katana",
        relations=[Relation("url", "https://b.example.com/api", "belongs_to", "host", "https://b.example.com")]))
    store.persist_normalization(ctx.run_id, Normalizer().normalize(records))
    Triage().run(ctx)
    return ctx, store


def test_per_host_scope_represents_every_subdomain():
    # global top_n could let the noisy host crowd out the quiet one; per_host won't.
    ctx, store = _multi_host_ctx({
        "context": "curated", "context_scope": "per_host",
        "context_per_host": 1, "context_include_host_roots": True, "context_max_nodes": 60,
    })
    keys = {n["key"] for n in _curated_payload(ctx)["nodes"]}
    # both host roots present
    assert {"https://a.example.com", "https://b.example.com"} <= keys
    # the quiet subdomain's single URL is represented
    assert "https://b.example.com/api" in keys
    # only ONE URL per host (per_host=1): a.example.com contributes exactly one of its four
    a_urls = [k for k in keys if k.startswith("https://a.example.com/")]
    assert len(a_urls) == 1
    store.close()


def test_global_scope_can_omit_quiet_host_urls():
    # contrast: with a tiny global budget, the quiet host's URL may not make the cut
    ctx, store = _multi_host_ctx({
        "context": "curated", "context_scope": "global", "context_top_n": 2, "context_max_nodes": 60,
    })
    url_keys = [n["key"] for n in _curated_payload(ctx)["nodes"] if "/" in n["key"].split("://", 1)[1]]
    assert len(url_keys) <= 2  # global budget, not per-host
    store.close()


def test_full_context_returns_whole_graph():
    ctx, store = _ctx({"context": "full"})
    keys = {n["key"] for n in _curated_payload(ctx)["nodes"]}
    assert any(k.endswith("/n0") for k in keys)  # neutral URLs present in full graph
    store.close()


def test_fallback_to_full_graph_when_no_triage():
    ctx, store = _ctx({"context": "curated"}, run_triage=False)
    keys = {n["key"] for n in _curated_payload(ctx)["nodes"]}
    assert any(k.endswith("/n0") for k in keys)  # no triage ranking -> full graph
    store.close()
