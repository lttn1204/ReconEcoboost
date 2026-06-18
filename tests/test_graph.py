"""Tests for the SQLite-backed knowledge graph."""

from datetime import datetime, timezone

from reconecoboost.core.entities import Relation
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.graph import SqliteKnowledgeGraph
from reconecoboost.persistence import Database, Store


class _Domain:
    value = "web"


class _Config:
    raw = {}


class _Ctx:
    run_id = "graphrun01"
    domain = _Domain()
    profile = "default"
    config = _Config()
    created_at = datetime(2026, 6, 16, tzinfo=timezone.utc)

    class scope:
        targets = ["example.com"]
        in_scope: list = []
        out_of_scope: list = []


def _seed_store():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    store.start_run(_Ctx())

    records = [
        ParsedRecord("subdomain", "a.example.com", tool="subfinder"),
        ParsedRecord(
            "host", "https://a.example.com", tool="httpx",
            relations=[Relation("subdomain", "a.example.com", "resolves_to", "host", "https://a.example.com")],
        ),
        ParsedRecord(
            "url", "https://a.example.com/login", tool="katana",
            relations=[Relation("url", "https://a.example.com/login", "belongs_to", "host", "https://a.example.com")],
        ),
    ]
    store.persist_normalization(_Ctx.run_id, Normalizer().normalize(records))
    return store


def _id(store, asset_type):
    return store.list_assets(_Ctx.run_id, asset_type)[0]["id"]


def test_nodes_and_edges_counts():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    assert len(graph.nodes(_Ctx.run_id)) == 3
    assert len(graph.edges(_Ctx.run_id)) == 2
    store.close()


def test_neighbors_both_directions():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    host_id = _id(store, "host")
    neighbors = graph.neighbors(_Ctx.run_id, host_id, direction="both")
    types = {node.asset_type for _, node in neighbors}
    assert types == {"subdomain", "url"}
    store.close()


def test_neighborhood_induced_subgraph():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    host_id = _id(store, "host")
    sub = graph.neighborhood(_Ctx.run_id, host_id, hops=1)
    assert sub.node_count == 3
    assert sub.edge_count == 2
    store.close()


def test_find_chains_by_rel_sequence():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    assert len(graph.find_chains(_Ctx.run_id, ["resolves_to"])) == 1
    assert len(graph.find_chains(_Ctx.run_id, ["belongs_to"])) == 1
    assert graph.find_chains(_Ctx.run_id, ["nonexistent"]) == []
    store.close()


def test_paths_undirected():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    sub_id = _id(store, "subdomain")
    url_id = _id(store, "url")
    # subdomain -> host <- url: no directed path, but undirected reaches it
    assert graph.paths(_Ctx.run_id, sub_id, url_id, directed=True) == []
    assert len(graph.paths(_Ctx.run_id, sub_id, url_id, directed=False)) >= 1
    store.close()


def test_subgraph_by_type_with_hops():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    sub = graph.subgraph(_Ctx.run_id, asset_types=["host"], hops=1)
    # host plus its 1-hop neighbors (subdomain, url)
    assert sub.node_count == 3
    store.close()


def test_to_prompt_dict_shape():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    sub = graph.neighborhood(_Ctx.run_id, _id(store, "host"), hops=1)
    payload = sub.to_prompt_dict()
    assert len(payload["nodes"]) == 3
    assert len(payload["edges"]) == 2
    assert {e["rel"] for e in payload["edges"]} == {"resolves_to", "belongs_to"}
    store.close()


def test_stats():
    store = _seed_store()
    graph = SqliteKnowledgeGraph(store.db)
    stats = graph.stats(_Ctx.run_id)
    assert stats["nodes"] == {"subdomain": 1, "host": 1, "url": 1}
    assert stats["edges"] == {"resolves_to": 1, "belongs_to": 1}
    store.close()
