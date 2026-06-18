"""KnowledgeGraph interface.

The abstraction the rest of the framework (and the AI layer) depends on. v1 ships
a SQLite-backed implementation; a dedicated graph DB (Neo4j/Memgraph) can replace
it later without touching callers (architecture doc 10).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from .models import GraphEdge, GraphNode, Subgraph


class KnowledgeGraph(ABC):
    """Read interface over the typed, directed knowledge graph."""

    @abstractmethod
    def node(self, asset_id: int) -> GraphNode | None:
        """Fetch a single node by asset id."""

    @abstractmethod
    def nodes(self, run_id: str, asset_type: str | None = None) -> list[GraphNode]:
        """All nodes for a run, optionally filtered by asset type."""

    @abstractmethod
    def edges(self, run_id: str, rel_type: str | None = None) -> list[GraphEdge]:
        """All edges for a run, optionally filtered by relation type."""

    @abstractmethod
    def neighbors(
        self,
        run_id: str,
        asset_id: int,
        direction: str = "both",
        rel_type: str | None = None,
    ) -> list[tuple[GraphEdge, GraphNode]]:
        """One-hop neighbors of a node (direction: 'out' | 'in' | 'both')."""

    @abstractmethod
    def neighborhood(self, run_id: str, asset_id: int, hops: int = 1) -> Subgraph:
        """The k-hop neighborhood around a node, as an induced subgraph."""

    @abstractmethod
    def subgraph(
        self,
        run_id: str,
        seed_ids: list[int] | None = None,
        asset_types: list[str] | None = None,
        hops: int = 0,
    ) -> Subgraph:
        """A curated slice: seeds (by id or type) expanded by ``hops``."""

    @abstractmethod
    def paths(
        self,
        run_id: str,
        src_id: int,
        dst_id: int,
        max_depth: int = 4,
        directed: bool = True,
    ) -> list[list[GraphEdge]]:
        """All simple paths between two nodes up to ``max_depth`` edges."""

    @abstractmethod
    def find_chains(self, run_id: str, rel_sequence: list[str]) -> list[list[GraphEdge]]:
        """All directed paths whose edge types match ``rel_sequence`` in order."""

    @abstractmethod
    def stats(self, run_id: str) -> dict[str, dict[str, int]]:
        """Counts of nodes by asset_type and edges by rel_type."""
