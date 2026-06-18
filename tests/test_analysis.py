"""Tests for the AI analysis modules (graph -> prompt -> structured -> findings)."""

from reconecoboost.ai import StubProvider
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.entities import Relation
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.graph import SqliteKnowledgeGraph
from reconecoboost.persistence import Database, Store
from reconecoboost.analysis.web import AiPentest, AiReconIntel


def _seed_ctx(provider):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)

    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(),  # empty ai config -> prompts dir defaults to "prompts"
        repository=store,
        graph=SqliteKnowledgeGraph(db),
        ai=provider,
    )
    store.start_run(ctx)

    records = [
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
        ParsedRecord(
            "url", "https://a.example.com/login", tool="katana",
            relations=[Relation("url", "https://a.example.com/login", "belongs_to", "host", "https://a.example.com")],
        ),
    ]
    store.persist_normalization(ctx.run_id, Normalizer().normalize(records))
    return ctx, store


def test_ai_recon_intel_stores_findings():
    canned = {
        "technologies": [{"name": "DNN", "note": "Known CMS, check default admin"}],
        "interesting_endpoints": [{"url": "https://a.example.com/login", "reason": "auth"}],
        "sensitive_findings": [
            {"title": "Login exposed", "detail": "form at /login", "where": "https://a.example.com/login", "severity": "medium"}
        ],
        "notes": ["test auth rate limiting"],
    }
    ctx, store = _seed_ctx(StubProvider(parsed=canned))

    result = AiReconIntel().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    # consolidated intel finding + 1 sensitive finding
    assert result.produced == 2
    findings = store.list_findings(ctx.run_id)
    kinds = {f["kind"] for f in findings}
    assert kinds == {"recon_intel"}
    titles = {f["title"] for f in findings}
    assert "Login exposed" in titles
    store.close()


def test_ai_pentest_stores_vulnerabilities():
    canned = {
        "vulnerabilities": [
            {
                "title": "Missing rate limiting on login",
                "vuln_type": "auth",
                "target": "https://a.example.com/login",
                "severity": "high",
                "confidence": "medium",
                "rationale": "Public login endpoint",
                "test_steps": ["enumerate users", "test lockout"],
            }
        ]
    }
    ctx, store = _seed_ctx(StubProvider(parsed=canned))

    result = AiPentest().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert result.produced == 1
    findings = store.list_findings(ctx.run_id)
    assert findings[0]["kind"] == "vulnerability"
    assert findings[0]["title"] == "Missing rate limiting on login"
    store.close()


def test_ai_recon_intel_no_nodes_is_noop():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"]),
        config=Config(),
        repository=store,
        graph=SqliteKnowledgeGraph(db),
        ai=StubProvider(),
    )
    store.start_run(ctx)

    result = AiReconIntel().run(ctx)
    assert result.status == ModuleStatus.SUCCESS
    assert result.produced == 0
    store.close()
