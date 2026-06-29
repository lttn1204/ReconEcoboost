"""Tests for the AI analysis modules (graph -> prompt -> structured -> findings)."""

import json

from reconecoboost.ai import StubProvider
from reconecoboost.ai.base import AIProvider, AIResponse
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


class _SeqStub(AIProvider):
    """Returns a queued parsed payload per call (clamps to the last)."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def generate(self, prompt, *, schema=None, system=None, max_tokens=None, effort=None):
        parsed = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return AIResponse(text=json.dumps(parsed), parsed=parsed, model="seq")


def _vuln(title):
    return {
        "title": title, "vuln_type": "info disclosure",
        "target": "https://a.example.com/login", "severity": "medium",
        "confidence": "low", "confidence_score": 5, "rationale": "r",
        "evidence": "GET /login -> 200", "impact": "i", "test_steps": ["s"],
        "poc": "curl https://a.example.com/login",
    }


def _pentest_payload(titles, analysis="a"):
    return {
        "analysis": analysis, "tech_stack": [], "manual_next_steps": [],
        "vulnerabilities": [_vuln(t) for t in titles],
    }


def test_ai_pentest_two_stage_uses_verify_pass():
    pass1 = _pentest_payload(["Lead A", "Weak B"], analysis="first pass")
    pass2 = _pentest_payload(["Lead A"], analysis="dropped Weak B")
    stub = _SeqStub([pass1, pass2])
    ctx, store = _seed_ctx(stub)
    ctx.config.ai = {"prompt_version": "v4", "two_stage": True}

    result = AiPentest().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert stub.calls == 2  # first pass + verify pass
    vulns = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "vulnerability"]
    assert {v["title"] for v in vulns} == {"Lead A"}  # verify pass result used
    store.close()


def test_ai_pentest_two_stage_skips_without_verify_prompt():
    stub = _SeqStub([_pentest_payload(["Lead A"])])
    ctx, store = _seed_ctx(stub)
    ctx.config.ai = {"prompt_version": "v1", "two_stage": True}  # no v1 pentest_verify

    result = AiPentest().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert stub.calls == 1  # second pass skipped (no verify prompt)
    vulns = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "vulnerability"]
    assert {v["title"] for v in vulns} == {"Lead A"}
    store.close()


class _SchemaStub(AIProvider):
    """Returns a plan for ACTION_PLAN_SCHEMA calls, a pentest payload otherwise."""

    def __init__(self, plans, pentest):
        self._plans = list(plans)
        self._pentest = pentest
        self.plan_calls = 0
        self.pentest_calls = 0

    def generate(self, prompt, *, schema=None, system=None, max_tokens=None, effort=None):
        props = (schema or {}).get("properties", {})
        if "actions" in props:  # action-plan schema
            payload = self._plans[min(self.plan_calls, len(self._plans) - 1)]
            self.plan_calls += 1
        else:
            payload = self._pentest
            self.pentest_calls += 1
        return AIResponse(text=json.dumps(payload), parsed=payload, model="schema-stub")


def test_ai_pentest_agentic_loop(monkeypatch, tmp_path):
    import httpx

    def fake_ensure(self):
        if self._client is None:
            self._client = httpx.Client(
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(200, text="hello " + req.url.path)),
                follow_redirects=False)
        return self._client

    monkeypatch.setattr(
        "reconecoboost.analysis.agent_http.AgentHttp._ensure_client", fake_ensure)

    plan = {
        "thought": "probe login", "done": True,
        "actions": [{"method": "GET", "url": "https://example.com/login",
                     "headers": [], "body": "", "reason": "check login",
                     "expect": "200"}],
        "proposed_fuzz": {"endpoints": ["/api/v1"], "params": ["id"],
                          "dirwords": ["admin"], "subwords": ["dev"]},
    }
    stub = _SchemaStub([plan], _pentest_payload(["Exposed config"]))
    ctx, store = _seed_ctx(stub)
    ctx.results_dir = str(tmp_path)
    ctx.config.ai = {
        "prompt_version": "v5",
        "agentic": {"enabled": True, "max_iterations": 2, "max_requests": 10,
                    "per_iteration_actions": 5, "rate_per_s": 0},
    }

    result = AiPentest().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert result.meta["agentic"] is True
    assert result.meta["probes"] == 1
    assert stub.plan_calls == 1 and stub.pentest_calls == 1

    findings = store.list_findings(ctx.run_id)
    kinds = {f["kind"] for f in findings}
    assert {"vulnerability", "agent_log", "recon_note"} <= kinds
    # C: agent-proposed seeds exported to the AI-seam files the fuzzers read
    assert (tmp_path / "ai_params.txt").read_text().strip() == "id"
    assert (tmp_path / "ai_endpoints.txt").read_text().strip() == "/api/v1"
    store.close()


def test_ai_pentest_agentic_refuses_out_of_scope_probe(monkeypatch, tmp_path):
    import httpx

    def fake_ensure(self):
        if self._client is None:
            self._client = httpx.Client(
                transport=httpx.MockTransport(lambda req: httpx.Response(200)),
                follow_redirects=False)
        return self._client

    monkeypatch.setattr(
        "reconecoboost.analysis.agent_http.AgentHttp._ensure_client", fake_ensure)

    plan = {
        "thought": "try external", "done": True,
        "actions": [{"method": "GET", "url": "https://evil.com/", "headers": [],
                     "body": "", "reason": "oob", "expect": "x"}],
        "proposed_fuzz": {"endpoints": [], "params": [], "dirwords": [], "subwords": []},
    }
    stub = _SchemaStub([plan], _pentest_payload([]))
    ctx, store = _seed_ctx(stub)
    ctx.results_dir = str(tmp_path)
    ctx.config.ai = {"prompt_version": "v5",
                     "agentic": {"enabled": True, "rate_per_s": 0}}

    AiPentest().run(ctx)

    log = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "agent_log"][0]
    req = json.loads(log["detail_json"])["requests"][0]
    assert "REFUSED" in req["result"] and "out of scope" in req["result"]
    store.close()


class _QuotaStub(AIProvider):
    """Returns plan/pentest by schema, but raises a quota AIError on chosen call #s."""

    def __init__(self, plan, pentest, raise_on=()):
        self.plan = plan
        self.pentest = pentest
        self.raise_on = set(raise_on)
        self.calls = 0

    def generate(self, prompt, *, schema=None, system=None, max_tokens=None, effort=None):
        from reconecoboost.core.errors import AIError
        self.calls += 1
        if self.calls in self.raise_on:
            raise AIError("Claude Code reported an error: usage limit reached, resets at 5pm")
        props = (schema or {}).get("properties", {})
        payload = self.plan if "actions" in props else self.pentest
        return AIResponse(text=json.dumps(payload), parsed=payload, model="quota-stub")


def _agentic_ctx(provider, tmp_path):
    ctx, store = _seed_ctx(provider)
    ctx.results_dir = str(tmp_path)
    ctx.config.ai = {"prompt_version": "v5",
                     "agentic": {"enabled": True, "rate_per_s": 0, "max_iterations": 2}}
    return ctx, store


_AGENT_PLAN = {
    "thought": "probe", "done": True,
    "actions": [{"method": "GET", "url": "https://example.com/x", "headers": [],
                 "body": "", "reason": "r", "expect": "e"}],
    "proposed_fuzz": {"endpoints": [], "params": [], "dirwords": [], "subwords": []},
}


def _mock_transport(monkeypatch):
    import httpx
    def fake_ensure(self):
        if self._client is None:
            self._client = httpx.Client(
                transport=httpx.MockTransport(lambda req: httpx.Response(200, text="ok")),
                follow_redirects=False)
        return self._client
    monkeypatch.setattr(
        "reconecoboost.analysis.agent_http.AgentHttp._ensure_client", fake_ensure)


def test_agentic_pauses_on_quota_and_checkpoints(monkeypatch, tmp_path):
    _mock_transport(monkeypatch)
    # call 1 = plan (ok), call 2 = synthesis (quota) -> pause
    stub = _QuotaStub(_AGENT_PLAN, _pentest_payload(["Confirmed"]), raise_on=(2,))
    ctx, store = _agentic_ctx(stub, tmp_path)

    result = AiPentest().run(ctx)

    assert result.meta["paused"] is True
    assert "usage limit" in result.meta["reason"]
    assert (tmp_path / "agentic_state.json").exists()  # checkpoint kept for resume
    findings = store.list_findings(ctx.run_id)
    kinds = {f["kind"] for f in findings}
    assert "agent_log" in kinds          # probes preserved
    assert "vulnerability" not in kinds  # synthesis never completed
    store.close()


def test_agentic_resumes_from_checkpoint(monkeypatch, tmp_path):
    _mock_transport(monkeypatch)
    # 1st run pauses at synthesis (call 2)
    stub1 = _QuotaStub(_AGENT_PLAN, _pentest_payload(["Confirmed"]), raise_on=(2,))
    ctx, store = _agentic_ctx(stub1, tmp_path)
    AiPentest().run(ctx)
    assert (tmp_path / "agentic_state.json").exists()

    # 2nd run: quota back. Resume should SKIP the probe loop (loop_done) and only synthesize.
    stub2 = _QuotaStub(_AGENT_PLAN, _pentest_payload(["Confirmed"]))
    ctx.ai = stub2
    result = AiPentest().run(ctx)

    assert result.meta.get("paused") is False
    assert result.produced == 1                    # synthesis completed this time
    assert stub2.calls == 1                         # loop skipped — only the synthesis call
    assert not (tmp_path / "agentic_state.json").exists()  # checkpoint cleared on success
    assert any(f["kind"] == "vulnerability" for f in store.list_findings(ctx.run_id))
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
