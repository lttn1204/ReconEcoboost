"""Database connection manager (SQLite).

Thin wrapper over ``sqlite3``: owns the connection, enables foreign keys and WAL
(for file-backed DBs), initializes the schema, and provides a transaction
context manager. The rest of the code talks to repositories, never to this
class directly (architecture doc 09).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .schema import SCHEMA


class Database:
    """Owns a single SQLite connection and its lifecycle."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        return self._conn

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
        self._conn = conn
        return conn

    def initialize(self) -> "Database":
        """Create tables/indexes if they do not exist. Idempotent."""
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        return self

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a unit of work, committing on success and rolling back on error."""
        conn = self.conn
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
