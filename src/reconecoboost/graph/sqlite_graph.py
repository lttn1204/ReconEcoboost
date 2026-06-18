"""SQLite-backed knowledge graph (graph-on-SQL).

Nodes are ``asset`` rows, edges are ``relation`` rows. Node/edge fetches and the
k-hop reachable set use SQL (the reachable set via a recursive CTE); path and
chain *enumeration* are done in Python over an in-memory adjacency map, which is
clearer and more portable than expressing path enumeration in SQL. The whole
class sits behind :class:`KnowledgeGraph` so a real graph DB can replace it
later (architecture doc 10).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from .base import KnowledgeGraph
from .models import GraphEdge, GraphNode, Subgraph

if TYPE_CHECKING:
    from ..persistence.database import Database


class SqliteKnowledgeGraph(KnowledgeGraph):
    def __init__(self, db: "Database") -> None:
        self._db = db

    @property
    def _conn(self):
        return self._db.conn

    # -- node/edge fetch (SQL) ---------------------------------------------

    @staticmethod
    def _node(row) -> GraphNode:
        return GraphNode(
            id=row["id"],
            asset_type=row["asset_type"],
            key=row["canonical_key"],
            attributes=json.loads(row["attributes_json"] or "{}"),
        )

    @staticmethod
    def _edge(row) -> GraphEdge:
        return GraphEdge(
            id=row["id"],
            src_id=row["src_asset_id"],
            dst_id=row["dst_asset_id"],
            rel_type=row["rel_type"],
            confidence=row["confidence"],
            source=row["source"],
        )

    def node(self, asset_id: int) -> GraphNode | None:
        row = self._conn.execute("SELECT * FROM asset WHERE id = ?", (asset_id,)).fetchone()
        return self._node(row) if row else None

    def nodes(self, run_id: str, asset_type: str | None = None) -> list[GraphNode]:
        if asset_type is not None:
            rows = self._conn.execute(
                "SELECT * FROM asset WHERE run_id = ? AND asset_type = ? ORDER BY id",
                (run_id, asset_type),
            )
        else:
            rows = self._conn.execute(
                "SELECT * FROM asset WHERE run_id = ? ORDER BY id", (run_id,)
            )
        return [self._node(r) for r in rows]

    def edges(self, run_id: str, rel_type: str | None = None) -> list[GraphEdge]:
        if rel_type is not None:
            rows = self._conn.execute(
                "SELECT * FROM relation WHERE run_id = ? AND rel_type = ? ORDER BY id",
                (run_id, rel_type),
            )
        else:
            rows = self._conn.execute(
                "SELECT * FROM relation WHERE run_id = ? ORDER BY id", (run_id,)
            )
        return [self._edge(r) for r in rows]

    # -- traversal ----------------------------------------------------------

    def neighbors(
        self,
        run_id: str,
        asset_id: int,
        direction: str = "both",
        rel_type: str | None = None,
    ) -> list[tuple[GraphEdge, GraphNode]]:
        out: list[tuple[GraphEdge, GraphNode]] = []
        for edge in self.edges(run_id, rel_type):
            if direction in ("out", "both") and edge.src_id == asset_id:
                node = self.node(edge.dst_id)
                if node:
                    out.append((edge, node))
            if direction in ("in", "both") and edge.dst_id == asset_id:
                node = self.node(edge.src_id)
                if node:
                    out.append((edge, node))
        return out

    def _reachable_ids(self, run_id: str, start_id: int, hops: int) -> set[int]:
        """k-hop undirected reachable set via a recursive CTE."""
        query = """
            WITH RECURSIVE reach(id, depth) AS (
                VALUES(?, 0)
                UNION
                SELECT
                    CASE WHEN r.src_asset_id = reach.id
                         THEN r.dst_asset_id ELSE r.src_asset_id END,
                    reach.depth + 1
                FROM relation r
                JOIN reach
                  ON (r.src_asset_id = reach.id OR r.dst_asset_id = reach.id)
                WHERE r.run_id = ? AND reach.depth < ?
            )
            SELECT DISTINCT id FROM reach
        """
        rows = self._conn.execute(query, (start_id, run_id, hops))
        return {row["id"] for row in rows}

    def _induced(self, run_id: str, ids: set[int]) -> Subgraph:
        sub = Subgraph()
        for nid in ids:
            node = self.node(nid)
            if node:
                sub.nodes[nid] = node
        for edge in self.edges(run_id):
            if edge.src_id in ids and edge.dst_id in ids:
                sub.edges.append(edge)
        return sub

    def neighborhood(self, run_id: str, asset_id: int, hops: int = 1) -> Subgraph:
        ids = self._reachable_ids(run_id, asset_id, hops) | {asset_id}
        return self._induced(run_id, ids)

    def subgraph(
        self,
        run_id: str,
        seed_ids: list[int] | None = None,
        asset_types: list[str] | None = None,
        hops: int = 0,
    ) -> Subgraph:
        seeds: set[int] = set(seed_ids or [])
        if asset_types:
            for asset_type in asset_types:
                seeds.update(n.id for n in self.nodes(run_id, asset_type))

        ids = set(seeds)
        for seed in seeds:
            if hops > 0:
                ids |= self._reachable_ids(run_id, seed, hops)
        return self._induced(run_id, ids)

    def paths(
        self,
        run_id: str,
        src_id: int,
        dst_id: int,
        max_depth: int = 4,
        directed: bool = True,
    ) -> list[list[GraphEdge]]:
        adj = self._full_adjacency(run_id, directed)
        results: list[list[GraphEdge]] = []

        def dfs(node: int, trail: list[GraphEdge], visited: set[int]) -> None:
            if len(trail) > max_depth:
                return
            if node == dst_id and trail:
                results.append(list(trail))
                return
            for edge, nxt in adj.get(node, []):
                if nxt in visited:
                    continue
                visited.add(nxt)
                trail.append(edge)
                dfs(nxt, trail, visited)
                trail.pop()
                visited.discard(nxt)

        dfs(src_id, [], {src_id})
        return results

    def find_chains(self, run_id: str, rel_sequence: list[str]) -> list[list[GraphEdge]]:
        if not rel_sequence:
            return []
        adj = self._full_adjacency(run_id, directed=True)
        results: list[list[GraphEdge]] = []

        def extend(node: int, idx: int, trail: list[GraphEdge]) -> None:
            if idx == len(rel_sequence):
                results.append(list(trail))
                return
            for edge, nxt in adj.get(node, []):
                if edge.rel_type == rel_sequence[idx]:
                    trail.append(edge)
                    extend(nxt, idx + 1, trail)
                    trail.pop()

        for node_id in self._all_node_ids(run_id):
            extend(node_id, 0, [])
        return results

    def stats(self, run_id: str) -> dict[str, dict[str, int]]:
        node_rows = self._conn.execute(
            "SELECT asset_type, COUNT(*) AS c FROM asset WHERE run_id = ? GROUP BY asset_type",
            (run_id,),
        )
        edge_rows = self._conn.execute(
            "SELECT rel_type, COUNT(*) AS c FROM relation WHERE run_id = ? GROUP BY rel_type",
            (run_id,),
        )
        return {
            "nodes": {r["asset_type"]: r["c"] for r in node_rows},
            "edges": {r["rel_type"]: r["c"] for r in edge_rows},
        }

    # -- helpers ------------------------------------------------------------

    def _all_node_ids(self, run_id: str) -> list[int]:
        rows = self._conn.execute("SELECT id FROM asset WHERE run_id = ?", (run_id,))
        return [r["id"] for r in rows]

    def _full_adjacency(self, run_id: str, directed: bool) -> dict[int, list[tuple[GraphEdge, int]]]:
        adj: dict[int, list[tuple[GraphEdge, int]]] = {}
        for edge in self.edges(run_id):
            adj.setdefault(edge.src_id, []).append((edge, edge.dst_id))
            if not directed:
                adj.setdefault(edge.dst_id, []).append((edge, edge.src_id))
        return adj
