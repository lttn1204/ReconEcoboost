"""In-memory graph data structures.

A :class:`Subgraph` is what the analysis/AI layer consumes — a curated slice of
the knowledge graph (never the whole thing), serialized into a compact, typed
structure for prompting (architecture doc 10).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    """A node in the graph — backed by an ``asset`` row."""

    id: int
    asset_type: str
    key: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A directed, typed edge — backed by a ``relation`` row."""

    id: int
    src_id: int
    dst_id: int
    rel_type: str
    confidence: float = 1.0
    source: str | None = None


@dataclass
class Subgraph:
    """A bounded set of nodes and the edges induced among them."""

    nodes: dict[int, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def adjacency(self, directed: bool = True) -> dict[int, list[tuple[GraphEdge, int]]]:
        """Build an adjacency map node_id -> [(edge, neighbor_id), ...]."""
        adj: dict[int, list[tuple[GraphEdge, int]]] = {nid: [] for nid in self.nodes}
        for edge in self.edges:
            adj.setdefault(edge.src_id, []).append((edge, edge.dst_id))
            if not directed:
                adj.setdefault(edge.dst_id, []).append((edge, edge.src_id))
        return adj

    def to_prompt_dict(self) -> dict[str, Any]:
        """Serialize to a compact, typed structure for the AI layer.

        Edges reference node *keys* (human/AI-readable) rather than ids, and only
        edges whose endpoints are present in this subgraph are included.
        """
        nodes = [
            {"type": n.asset_type, "key": n.key, "attributes": n.attributes}
            for n in self.nodes.values()
        ]
        edges = [
            {
                "src": self.nodes[e.src_id].key,
                "rel": e.rel_type,
                "dst": self.nodes[e.dst_id].key,
            }
            for e in self.edges
            if e.src_id in self.nodes and e.dst_id in self.nodes
        ]
        return {"nodes": nodes, "edges": edges}
