"""Tests for the subdomain permutation module (alterx -> dnsx)."""

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
from reconecoboost.modules.web.permutation import Permutation
from reconecoboost.persistence import Database, Store


class FakeTools:
    def __init__(self, missing=()):
        self.missing = set(missing)

    def resolve(self, name):
        if name in self.missing:
            raise ToolNotFoundError(f"tool '{name}' not found")
        return ToolHandle(name=name, binary=name, path=f"/usr/bin/{name}")

    def version(self, name):
        return "1.0"


class FakeExecutor:
    """Returns alterx output for the alterx call, dnsx output for the dnsx call."""

    def __init__(self, alterx_out="", dnsx_out=""):
        self.alterx_out = alterx_out
        self.dnsx_out = dnsx_out
        self.calls = []

    def run(self, argv, *, timeout_s=None, input_text=None, capture_to=None):
        self.calls.append((argv, input_text))
        out = self.alterx_out if "alterx" in " ".join(argv) else self.dnsx_out
        return ExecutionResult(argv=argv, status=ExecutionStatus.SUCCESS,
                               exit_code=0, stdout=out, duration_s=0.1)

    def dnsx_input(self):
        return next((inp for argv, inp in self.calls if "dnsx" in " ".join(argv)), "")


def _store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def _ctx(store, ex, tmp_path, *, wildcard=True, pipeline=None, tools=None):
    in_scope = ["*.example.com"] if wildcard else ["example.com"]
    return Context(
        domain=Domain.WEB,
        scope=Scope(targets=["example.com"], in_scope=in_scope),
        config=Config(pipeline=pipeline or {}),
        executor=ex, tools=tools or FakeTools(), repository=store, results_dir=tmp_path,
    )


def _seed(store, ctx, *subs):
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize(
        [ParsedRecord("subdomain", s, tool="subfinder") for s in subs]))


def test_permutation_generates_and_resolves(tmp_path):
    store = _store()
    ex = FakeExecutor(
        alterx_out="api-dev.example.com\napi2.example.com\n",
        dnsx_out=json.dumps({"host": "api-dev.example.com", "a": ["1.2.3.4"]}),
    )
    ctx = _ctx(store, ex, tmp_path)
    _seed(store, ctx, "api.example.com")

    result = Permutation().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    # alterx candidates were fed to dnsx
    fed = set(ex.dnsx_input().split())
    assert {"api-dev.example.com", "api2.example.com"} <= fed
    # only the resolving candidate became an asset
    subs = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert "api-dev.example.com" in subs
    # summary written
    summary = (tmp_path / "permutation.txt").read_text()
    assert "api-dev.example.com" in summary and "1.2.3.4" in summary
    store.close()


def test_permutation_skipped_without_wildcard_scope(tmp_path):
    store = _store()
    ex = FakeExecutor(alterx_out="api2.example.com\n", dnsx_out="")
    ctx = _ctx(store, ex, tmp_path, wildcard=False)
    _seed(store, ctx, "example.com")

    result = Permutation().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    assert result.meta.get("skipped") == "no-wildcard-scope"
    assert ex.calls == []   # nothing executed
    store.close()


def test_permutation_disabled(tmp_path):
    store = _store()
    ex = FakeExecutor()
    ctx = _ctx(store, ex, tmp_path, pipeline={"permutation": {"enabled": False}})
    _seed(store, ctx, "api.example.com")

    result = Permutation().run(ctx)
    assert result.status == ModuleStatus.SUCCESS
    assert result.meta == {"disabled": True}
    assert ex.calls == []
    store.close()


def test_permutation_hard_fails_when_tool_missing(tmp_path):
    store = _store()
    ex = FakeExecutor()
    ctx = _ctx(store, ex, tmp_path, tools=FakeTools(missing={"alterx"}))
    _seed(store, ctx, "api.example.com")

    result = Permutation().run(ctx)
    assert result.status == ModuleStatus.FAILED
    assert "alterx" in (result.error or "")
    store.close()


def test_permutation_folds_ai_subwords_seam(tmp_path):
    (tmp_path / "ai_subwords.txt").write_text("# AI\nsecretpanel\n", encoding="utf-8")
    store = _store()
    ex = FakeExecutor(alterx_out="api2.example.com\n", dnsx_out="")
    ctx = _ctx(store, ex, tmp_path)
    _seed(store, ctx, "api.example.com")

    Permutation().run(ctx)

    fed = set(ex.dnsx_input().split())
    assert "secretpanel.example.com" in fed   # AI label folded in as label.<apex>
    store.close()


def test_permutation_drops_wildcard_noise(tmp_path):
    store = _store()
    # both the synthetic probes and one candidate resolve only to 9.9.9.9 (wildcard);
    # a real candidate resolves elsewhere and must survive.
    lines = [json.dumps({"host": f"zzz-wildcardcheck{i}-doesnotexist.example.com", "a": ["9.9.9.9"]})
             for i in range(3)]
    lines.append(json.dumps({"host": "ghost.example.com", "a": ["9.9.9.9"]}))      # wildcard FP
    lines.append(json.dumps({"host": "real.example.com", "a": ["1.2.3.4"]}))       # real
    ex = FakeExecutor(alterx_out="ghost.example.com\nreal.example.com\n",
                      dnsx_out="\n".join(lines))
    ctx = _ctx(store, ex, tmp_path)
    _seed(store, ctx, "api.example.com")

    Permutation().run(ctx)

    subs = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert "real.example.com" in subs
    assert "ghost.example.com" not in subs   # wildcard false positive dropped
    assert not any(s.startswith("zzz-wildcardcheck") for s in subs)  # probes never persisted
    store.close()
