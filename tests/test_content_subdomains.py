"""Tests for content-driven subdomain discovery (separate, toggleable step)."""

import json

from reconecoboost.analysis.content_subdomains import extract_subdomains
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.modules.web.content_subdomains import ContentSubdomains
from reconecoboost.persistence import Database, Store


# --- extractor ------------------------------------------------------------
def test_extract_scoped_subdomains_scheme_and_bare():
    text = (
        'see <a href="https://api-internal.example.com/x">; '
        'script src=//pay-uat.example.com/app.js ; '
        'bare mention dev.example.com here; '
        'third party cdn.other.org and notexample.com should be ignored; '
        'apex example.com itself excluded'
    )
    found = extract_subdomains(text, ["example.com"])
    assert found == {"api-internal.example.com", "pay-uat.example.com", "dev.example.com"}


# --- module ---------------------------------------------------------------
def _write_bodies(tmp_path, mapping):
    rdir = tmp_path / "responses"
    rdir.mkdir(parents=True, exist_ok=True)
    index = []
    for i, (url, body) in enumerate(mapping.items()):
        fname = f"body-{i:04d}.txt"
        (rdir / fname).write_text(body, encoding="utf-8")
        index.append({"url": url, "file": fname})
    (rdir / "index.json").write_text(json.dumps(index), encoding="utf-8")


def _ctx(store, tmp_path, enabled=True):
    return Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"], in_scope=["*.example.com"]),
        config=Config(pipeline={"content_subdomains": {"enabled": enabled}}),
        repository=store, results_dir=tmp_path,
    )


def test_content_subdomains_persists_and_saves(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    _write_bodies(tmp_path, {
        "https://example.com/": '<script src="https://pay-uat.example.com/a.js"></script> dev.example.com',
    })
    ctx = _ctx(store, tmp_path)
    store.start_run(ctx)

    result = ContentSubdomains().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    subs = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "subdomain")}
    assert {"pay-uat.example.com", "dev.example.com"} <= subs
    assert "pay-uat.example.com" in (tmp_path / "content_subdomains.txt").read_text()
    store.close()


def test_content_subdomains_disabled(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    _write_bodies(tmp_path, {"https://example.com/": "dev.example.com"})
    ctx = _ctx(store, tmp_path, enabled=False)
    store.start_run(ctx)
    result = ContentSubdomains().run(ctx)
    assert result.meta == {"disabled": True}
    assert store.list_assets(ctx.run_id, "subdomain") == []
    store.close()
