"""Tests for the nuclei vulnerability-scanning module (no live nuclei calls)."""

import json

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.errors import ToolNotFoundError
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ExecutionResult, ExecutionStatus, Normalizer, ParsedRecord, ToolHandle
from reconecoboost.modules.web.nuclei_scan import NucleiScan
from reconecoboost.persistence import Database, Store


class FakeTools:
    def resolve(self, name):
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "3.0.0"


class FakeExecutor:
    def __init__(self, stdout):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append((argv, input_text))
        return ExecutionResult(
            argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
            stdout=self.stdout, duration_s=1.0,
        )


_NUCLEI_JSONL = "\n".join([
    json.dumps({"template-id": "tech-detect", "info": {"name": "Tech Detect", "severity": "info"},
                "type": "http", "host": "https://a.example.com", "matched-at": "https://a.example.com"}),
    json.dumps({"template-id": "CVE-2021-9999", "info": {"name": "Example RCE", "severity": "critical",
                "tags": ["cve", "rce"]}, "type": "http", "host": "https://a.example.com",
                "matched-at": "https://a.example.com/vuln"}),
])


def _ctx(executor, store):
    return Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), executor=executor, tools=FakeTools(), repository=store,
    )


def _store_with_host():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    return store


def test_nuclei_writes_vulnerability_findings():
    store = _store_with_host()
    ex = FakeExecutor(_NUCLEI_JSONL)
    ctx = _ctx(ex, store)
    store.start_run(ctx)
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("host", "https://a.example.com", tool="httpx")])
    )

    result = NucleiScan().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert result.produced == 2
    findings = store.list_findings(ctx.run_id)
    assert all(f["kind"] == "vulnerability" for f in findings)
    sev = {f["severity"] for f in findings}
    assert "critical" in sev
    crit = next(f for f in findings if f["severity"] == "critical")
    assert "CVE-2021-9999" in crit["title"]
    # the live hosts were fed to nuclei on stdin
    assert "https://a.example.com" in ex.calls[0][1]
    # tool_run recorded
    assert store.list_tool_runs(ctx.run_id)[0]["tool"] == "nuclei"
    store.close()


def test_nuclei_default_scans_all_host_roots_not_urls():
    """Default: every live subdomain's host root is scanned; URLs are not."""
    store = _store_with_host()
    ex = FakeExecutor(_NUCLEI_JSONL)
    ctx = _ctx(ex, store)  # default config -> scan_urls off
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("host", "https://a.example.com", tool="httpx"),
        ParsedRecord("host", "https://b.example.com", tool="httpx"),  # another subdomain
        ParsedRecord("url", "https://a.example.com/admin", attributes={"status_code": 200}, tool="httpx"),
    ]))

    NucleiScan().run(ctx)

    fed = set(ex.calls[0][1].split())
    assert fed == {"https://a.example.com", "https://b.example.com"}  # both host roots, no URLs
    store.close()


def test_nuclei_no_hosts_is_noop():
    store = _store_with_host()
    ctx = _ctx(FakeExecutor(""), store)
    store.start_run(ctx)
    result = NucleiScan().run(ctx)
    assert result.status == ModuleStatus.SUCCESS
    assert result.produced == 0
    store.close()


def test_nuclei_missing_tool_skips():
    store = _store_with_host()

    class Missing:
        def resolve(self, name):
            raise ToolNotFoundError(name)

        def version(self, name):
            return None

    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), executor=FakeExecutor(""), tools=Missing(), repository=store,
    )
    store.start_run(ctx)
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("host", "https://a.example.com")])
    )
    result = NucleiScan().run(ctx)
    assert result.status == ModuleStatus.SKIPPED
    store.close()


def test_severity_and_rate_args_from_config():
    store = _store_with_host()
    ex = FakeExecutor(_NUCLEI_JSONL)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(tools={
            "defaults": {"rate_limit": 50},
            "tools": {"nuclei": {"rate_flag": "-rl", "severity": ["high", "critical"]}},
        }),
        executor=ex, tools=FakeTools(), repository=store,
    )
    store.start_run(ctx)
    store.persist_normalization(
        ctx.run_id, Normalizer().normalize([ParsedRecord("host", "https://a.example.com")])
    )

    NucleiScan().run(ctx)

    argv = ex.calls[0][0]
    assert "-severity" in argv
    assert argv[argv.index("-severity") + 1] == "high,critical"
    assert "-rl" in argv and argv[argv.index("-rl") + 1] == "50"
    store.close()
