"""Guardrails for the agentic AI-pentest HTTP client (scope/method/payload/budget)."""

import httpx

from reconecoboost.analysis.agent_http import AgentHttp
from reconecoboost.core.scope import Scope


def _client(scope, **kw):
    agent = AgentHttp(scope, **kw)
    # inject a mock transport so no real network is touched
    def handler(request):
        return httpx.Response(200, text=f"ok {request.url.host}")
    agent._client = httpx.Client(transport=httpx.MockTransport(handler),
                                 follow_redirects=False)
    return agent


def test_in_scope_get_succeeds():
    agent = _client(Scope(targets=["example.com"]))
    res = agent.request("GET", "https://example.com/a")
    assert res["ok"] and res["status"] == 200
    assert agent.count == 1


def test_out_of_scope_refused_and_not_sent():
    agent = _client(Scope(targets=["example.com"], in_scope=["*.example.com"]))
    res = agent.request("GET", "https://evil.com/")
    assert not res["ok"] and "out of scope" in res["refused"]
    assert agent.count == 0  # never hit the network


def test_empty_in_scope_does_not_allow_everything():
    # Scope.is_allowed would allow anything when in_scope is empty; the agent must not.
    agent = _client(Scope(targets=["example.com"]))
    res = agent.request("GET", "https://other.com/")
    assert not res["ok"] and "out of scope" in res["refused"]


def test_method_not_in_allowlist_refused():
    agent = _client(Scope(targets=["example.com"]), allowed_methods=["GET"])
    res = agent.request("POST", "https://example.com/x", body="a=1")
    assert not res["ok"] and "not in allowlist" in res["refused"]


def test_destructive_payload_refused():
    agent = _client(Scope(targets=["example.com"]), allowed_methods=["GET", "POST"])
    res = agent.request("POST", "https://example.com/q", body="x=1; DROP TABLE users")
    assert not res["ok"] and "destructive" in res["refused"]


def test_budget_cap_enforced():
    agent = _client(Scope(targets=["example.com"]), max_requests=1)
    assert agent.request("GET", "https://example.com/1")["ok"]
    blocked = agent.request("GET", "https://example.com/2")
    assert not blocked["ok"] and "budget" in blocked["refused"]


def test_non_http_scheme_refused():
    agent = _client(Scope(targets=["example.com"]))
    res = agent.request("GET", "ftp://example.com/x")
    assert not res["ok"] and "scheme" in res["refused"]
