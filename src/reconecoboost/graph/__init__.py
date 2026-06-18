"""Knowledge graph layer — typed, directed graph over the persistence store.

See architecture doc 10. v1 is SQLite-backed (graph-on-SQL); the
:class:`KnowledgeGraph` interface keeps it swappable for a dedicated graph DB.
"""

from .base import KnowledgeGraph
from .models import GraphEdge, GraphNode, Subgraph
from .sqlite_graph import SqliteKnowledgeGraph

__all__ = [
    "KnowledgeGraph",
    "SqliteKnowledgeGraph",
    "GraphNode",
    "GraphEdge",
    "Subgraph",
]
