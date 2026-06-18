"""Tests for the SQLite persistence spine (Store + repositories)."""

from datetime import datetime, timezone

from reconecoboost.core.entities import CanonicalEntity, Provenance, Relation
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.persistence import Database, Store


class _Scope:
    targets = ["example.com"]
    in_scope: list = []
    out_of_scope: list = []


class _Domain:
    value = "web"


class _Config:
    raw = {"tools": {}, "pipeline": {}, "wordlists": {}, "ai": {}}


class _Ctx:
    """Minimal stand-in for Context (avoids constructing the full object)."""

    run_id = "testrun0001"
    domain = _Domain()
    profile = "default"
    scope = _Scope()
    config = _Config()
    created_at = datetime(2026, 6, 16, tzinfo=timezone.utc)


def _open_memory_store() -> Store:
    db = Database(":memory:")
    db.connect()
    db.initialize()
    return Store(db)


def test_start_run_records_run_and_targets():
    store = _open_memory_store()
    ctx = _Ctx()
    store.start_run(ctx)
    run = store.get_run(ctx.run_id)
    assert run is not None
    assert run["domain"] == "web"
    assert run["status"] == "running"
    store.close()


def test_persist_normalization_dedupes_and_merges():
    store = _open_memory_store()
    ctx = _Ctx()
    store.start_run(ctx)

    records = [
        ParsedRecord("url", "https://x/a", attributes={"status": 200}, tool="katana"),
        ParsedRecord("url", "https://x/a", attributes={"length": 10}, tool="gau"),
    ]
    result = Normalizer().normalize(records)
    counts = store.persist_normalization(ctx.run_id, result)

    assert counts["assets"] == 1
    assets = store.list_assets(ctx.run_id, "url")
    assert len(assets) == 1
    assert '"status": 200' in assets[0]["attributes_json"]
    assert '"length": 10' in assets[0]["attributes_json"]
    store.close()


def test_provenance_is_deduplicated_across_persists():
    store = _open_memory_store()
    ctx = _Ctx()
    store.start_run(ctx)

    entity = CanonicalEntity(
        asset_type="subdomain",
        canonical_key="a.example.com",
        attributes={},
        sources=[Provenance(tool="subfinder")],
    )

    class _Res:
        entities = [entity]
        relations: list = []

    store.persist_normalization(ctx.run_id, _Res())
    store.persist_normalization(ctx.run_id, _Res())  # same source again

    rows = store.db.conn.execute("SELECT COUNT(*) AS c FROM provenance").fetchone()
    assert rows["c"] == 1
    store.close()


def test_relations_resolve_endpoints_to_assets():
    store = _open_memory_store()
    ctx = _Ctx()
    store.start_run(ctx)

    records = [
        ParsedRecord("host", "h.example.com", tool="httpx"),
        ParsedRecord("url", "https://h.example.com/x", tool="katana"),
    ]
    rel = Relation("host", "h.example.com", "serves", "url", "https://h.example.com/x")
    result = Normalizer().normalize(records, relations=[rel])

    counts = store.persist_normalization(ctx.run_id, result)
    assert counts["relations"] == 1
    relations = store.list_relations(ctx.run_id)
    assert len(relations) == 1
    assert relations[0]["rel_type"] == "serves"
    store.close()


def test_tool_run_and_finding_recorded():
    store = _open_memory_store()
    ctx = _Ctx()
    store.start_run(ctx)

    store.record_tool_run(
        ctx.run_id,
        tool="subfinder",
        module="asset_discovery",
        version="2.6.0",
        argv_redacted="subfinder -d example.com",
        exit_code=0,
        status="success",
        duration_s=1.23,
    )
    store.add_finding(
        ctx.run_id, kind="summary", title="Looks interesting", severity="info"
    )

    assert len(store.list_tool_runs(ctx.run_id)) == 1
    assert len(store.list_findings(ctx.run_id)) == 1
    store.close()


def test_finish_run_sets_status():
    store = _open_memory_store()
    ctx = _Ctx()
    store.start_run(ctx)
    store.finish_run(ctx.run_id, "completed")
    assert store.get_run(ctx.run_id)["status"] == "completed"
    store.close()
