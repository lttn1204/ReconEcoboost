"""Tests for JS intelligence (extractor + pipeline module)."""

import json

from reconecoboost.analysis.js_intel import extract
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.modules.web.js_intel import JsIntel
from reconecoboost.persistence import Database, Store


# --- extractor ------------------------------------------------------------
def test_extract_endpoints_hosts_cloud_sourcemap():
    js = (
        'fetch("/api/v2/internal/users");'
        'axios.post("/admin/delete-account");'
        'const API="https://api-staging.example.com/v1";'
        'const CDN="company-backups.s3.amazonaws.com";'
        'img.src="/assets/logo.png";'           # static -> skipped
        '//# sourceMappingURL=main.js.map'
    )
    out = extract(js)
    assert "/api/v2/internal/users" in out.endpoints
    assert "/admin/delete-account" in out.endpoints
    assert "/assets/logo.png" not in out.endpoints       # media skipped
    assert "api-staging.example.com" in out.hosts
    assert any("s3.amazonaws.com" in c for c in out.cloud)
    assert "main.js.map" in out.sourcemaps


# --- module (reads bodies cached by js_fetch) -----------------------------
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
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(pipeline={"js_intel": {"enabled": enabled}}),
        repository=store, results_dir=tmp_path,
    )


def test_js_intel_persists_endpoints_and_findings(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    body = ('fetch("/api/v2/users");const CDN="company-backups.s3.amazonaws.com";'
            '//# sourceMappingURL=app.js.map')
    _write_bodies(tmp_path, {"https://a.example.com/app.js": body})
    ctx = _ctx(store, tmp_path)
    store.start_run(ctx)

    result = JsIntel().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    # endpoint became a url asset (resolved against the JS file's origin)
    urls = {a["canonical_key"] for a in store.list_assets(ctx.run_id, "url")}
    assert "https://a.example.com/api/v2/users" in urls
    # cloud bucket + source map became findings
    kinds = [f["kind"] for f in store.list_findings(ctx.run_id)]
    titles = " ".join(f["title"] for f in store.list_findings(ctx.run_id))
    assert kinds.count("exposure") == 2
    assert "Cloud storage" in titles and "source map" in titles
    assert (tmp_path / "js_intel.json").exists()
    assert "/api/v2/users" in (tmp_path / "js_intel.txt").read_text()
    store.close()


def test_js_intel_disabled_via_config(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = _ctx(store, tmp_path, enabled=False)
    store.start_run(ctx)
    result = JsIntel().run(ctx)
    assert result.status == ModuleStatus.SUCCESS
    assert result.meta == {"disabled": True}
    store.close()
