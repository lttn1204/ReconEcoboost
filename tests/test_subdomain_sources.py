"""Tests for the GitHub/TLS subdomain + secret sources (tlsx, github-subdomains, trufflehog)."""

import json

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
from reconecoboost.modules.web.github_secrets import GithubSecrets
from reconecoboost.modules.web.github_subdomains import GithubSubdomains
from reconecoboost.modules.web.parsers import TlsxParser
from reconecoboost.modules.web.tls_intel import TlsIntel
from reconecoboost.persistence import Database, Store


# --- TlsxParser ------------------------------------------------------------
def test_tlsx_parser_san_cn_wildcard_dedup():
    raw = json.dumps({
        "host": "1.2.3.4",
        "subject_cn": "primary.example.com",
        "subject_an": ["api.example.com", "*.example.com", "api.example.com"],
    })
    keys = {r.key for r in TlsxParser().parse(raw)}
    assert "api.example.com" in keys
    assert "primary.example.com" in keys     # CN included
    assert "example.com" in keys             # wildcard reduced to apex
    assert "*.example.com" not in keys       # raw wildcard dropped


# --- shared fakes ----------------------------------------------------------
class FakeTools:
    def __init__(self, missing=()):
        self.missing = set(missing)

    def resolve(self, name):
        if name in self.missing:
            raise ToolNotFoundError(f"{name} not found")
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "1.0"


class StdoutExecutor:
    def __init__(self, stdout=""):
        self.stdout = stdout
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None, env=None):
        self.calls.append((argv, input_text, env))
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
                               stdout=self.stdout, duration_s=0.1)


def _store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def _ctx(store, tmp_path, executor, tools, pipeline=None, in_scope=("*.example.com",)):
    return Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"], in_scope=list(in_scope)),
        config=Config(pipeline=pipeline or {}), executor=executor, tools=tools,
        repository=store, results_dir=tmp_path,
    )


# --- tls_intel -------------------------------------------------------------
def test_tls_intel_persists_san_and_scope_filters(tmp_path):
    store = _store()
    out = "\n".join([
        json.dumps({"host": "api.example.com",
                    "subject_an": ["api.example.com", "dev.example.com", "other-corp.com"]}),
    ])
    ex = StdoutExecutor(out)
    ctx = _ctx(store, tmp_path, ex, FakeTools())
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("subdomain", "api.example.com", attributes={"resolved": True}, tool="dnsx"),
    ]))

    result = TlsIntel().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    subs = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert "dev.example.com" in subs            # new SAN subdomain persisted
    assert "other-corp.com" not in subs         # out-of-scope SAN dropped
    assert "dev.example.com" in (tmp_path / "tls_intel.txt").read_text()
    store.close()


# --- github_subdomains -----------------------------------------------------
class GhSubsExecutor:
    """Writes discovered subdomains to the -o file (like github-subdomains does)."""
    def __init__(self, subs):
        self.subs = subs
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None, env=None):
        self.calls.append((argv, env))
        if "-o" in argv:
            with open(argv[argv.index("-o") + 1], "w", encoding="utf-8") as fh:
                fh.write("\n".join(self.subs) + "\n")
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS, exit_code=0,
                               stdout="", duration_s=0.1)


def test_github_subdomains_skips_without_token(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, GhSubsExecutor([]), FakeTools())  # no token in config/env
    store.start_run(ctx)
    import os
    saved = os.environ.pop("GITHUB_TOKEN", None)
    try:
        result = GithubSubdomains().run(ctx)
    finally:
        if saved is not None:
            os.environ["GITHUB_TOKEN"] = saved
    assert result.status == ModuleStatus.SKIPPED
    store.close()


def test_github_subdomains_hard_fails_without_binary(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, GhSubsExecutor([]), FakeTools(missing={"github-subdomains"}))
    store.start_run(ctx)
    result = GithubSubdomains().run(ctx)
    assert result.status == ModuleStatus.FAILED
    store.close()


def test_github_subdomains_persists_and_scope_filters(tmp_path):
    store = _store()
    ex = GhSubsExecutor(["dev.example.com", "internal.example.com", "evil-other.com"])
    ctx = _ctx(store, tmp_path, ex, FakeTools(),
               {"github_subdomains": {"token": "ghp_fake"}})
    store.start_run(ctx)
    result = GithubSubdomains().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    subs = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert {"dev.example.com", "internal.example.com"} <= subs
    assert "evil-other.com" not in subs          # out-of-scope dropped
    # token passed via ENV, never on argv (audit-log hygiene)
    argv, env = ex.calls[0]
    assert "ghp_fake" not in " ".join(argv)
    assert env.get("GITHUB_TOKEN") == "ghp_fake"
    assert "dev.example.com" in (tmp_path / "github_subdomains.txt").read_text()
    store.close()


# --- github_secrets (trufflehog) -------------------------------------------
def _trufflehog_out():
    log = json.dumps({"level": "info-0", "logger": "trufflehog", "msg": "running source"})
    finding = json.dumps({
        "DetectorName": "AWS", "Verified": True, "Raw": "AKIAIOSFODNN7EXAMPLE",
        "SourceMetadata": {"Data": {"Github": {
            "repository": "https://github.com/acme/app",
            "file": "config/prod.env", "link": "https://github.com/acme/app/blob/x/config/prod.env"}}},
    })
    return log + "\n" + finding + "\n"


def test_github_secrets_skips_without_org(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, StdoutExecutor(), FakeTools(),
               {"github_secrets": {"token": "ghp_x"}})   # token but no orgs/repos
    store.start_run(ctx)
    result = GithubSecrets().run(ctx)
    assert result.status == ModuleStatus.SKIPPED
    store.close()


def test_github_secrets_parses_findings_and_writes_results(tmp_path):
    store = _store()
    ex = StdoutExecutor(_trufflehog_out())
    ctx = _ctx(store, tmp_path, ex, FakeTools(),
               {"github_secrets": {"token": "ghp_x", "orgs": ["acme"]}})
    store.start_run(ctx)

    result = GithubSecrets().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    findings = [f for f in store.list_findings(ctx.run_id) if f["kind"] == "secret"]
    assert len(findings) == 1                       # log line filtered, finding kept
    assert findings[0]["severity"] == "high"        # verified -> high
    detail = json.loads(findings[0]["detail_json"])
    assert detail["detector"] == "AWS" and detail["verified"] is True
    # token via env, org on argv
    argv, _input, env = ex.calls[0]
    assert "--org" in argv and "acme" in argv
    assert "ghp_x" not in " ".join(argv) and env.get("GITHUB_TOKEN") == "ghp_x"
    assert "AWS" in (tmp_path / "github_secrets.txt").read_text()
    assert json.loads((tmp_path / "github_secrets.json").read_text())[0]["detail"]["detector"] == "AWS"
    store.close()


def test_github_secrets_hard_fails_without_binary(tmp_path):
    store = _store()
    ctx = _ctx(store, tmp_path, StdoutExecutor(), FakeTools(missing={"trufflehog"}),
               {"github_secrets": {"token": "ghp_x", "orgs": ["acme"]}})
    store.start_run(ctx)
    result = GithubSecrets().run(ctx)
    assert result.status == ModuleStatus.FAILED
    store.close()
