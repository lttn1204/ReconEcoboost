"""Repository layer + Store facade.

Repositories encapsulate all SQL; callers pass domain objects and receive ids or
plain dicts. The :class:`Store` composes the repositories and exposes the
transactional, run-scoped operations modules actually use (start/finish a run,
record a tool invocation, persist a normalization result, add a finding).

Nothing above this layer sees SQL or the sqlite driver (architecture doc 09).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.entities import CanonicalEntity, Provenance, Relation, canonical_key
from .database import Database

if TYPE_CHECKING:
    from ..core.context import Context


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Repositories (SQL lives only here)                                           #
# --------------------------------------------------------------------------- #


class RunRepository:
    def create(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        domain: str,
        profile: str | None,
        scope_json: str,
        config_hash: str,
        status: str,
        created_at: str,
    ) -> str:
        conn.execute(
            "INSERT INTO run(id, domain, profile, scope_json, config_hash, status, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (run_id, domain, profile, scope_json, config_hash, status, created_at),
        )
        return run_id

    def set_status(
        self, conn: sqlite3.Connection, run_id: str, status: str, finished_at: str | None = None
    ) -> None:
        conn.execute(
            "UPDATE run SET status = ?, finished_at = ? WHERE id = ?",
            (status, finished_at, run_id),
        )

    def get(self, conn: sqlite3.Connection, run_id: str) -> dict[str, Any] | None:
        row = conn.execute("SELECT * FROM run WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None


class AssetRepository:
    def upsert(self, conn: sqlite3.Connection, run_id: str, entity: CanonicalEntity) -> int:
        row = conn.execute(
            "SELECT id, attributes_json FROM asset "
            "WHERE run_id = ? AND asset_type = ? AND canonical_key = ?",
            (run_id, entity.asset_type, entity.canonical_key),
        ).fetchone()
        now = _utcnow()

        if row is not None:
            merged = json.loads(row["attributes_json"] or "{}")
            merged.update({k: v for k, v in entity.attributes.items() if v is not None})
            conn.execute(
                "UPDATE asset SET attributes_json = ?, last_seen = ? WHERE id = ?",
                (json.dumps(merged, sort_keys=True), now, row["id"]),
            )
            return int(row["id"])

        cur = conn.execute(
            "INSERT INTO asset(run_id, asset_type, canonical_key, attributes_json, first_seen, last_seen) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (
                run_id,
                entity.asset_type,
                entity.canonical_key,
                json.dumps(entity.attributes, sort_keys=True),
                now,
                now,
            ),
        )
        return int(cur.lastrowid)

    def find_id(
        self, conn: sqlite3.Connection, run_id: str, asset_type: str, key: str
    ) -> int | None:
        row = conn.execute(
            "SELECT id FROM asset WHERE run_id = ? AND asset_type = ? AND canonical_key = ?",
            (run_id, asset_type, key),
        ).fetchone()
        return int(row["id"]) if row else None

    def list(
        self, conn: sqlite3.Connection, run_id: str, asset_type: str | None = None
    ) -> list[dict[str, Any]]:
        if asset_type is not None:
            rows = conn.execute(
                "SELECT * FROM asset WHERE run_id = ? AND asset_type = ? ORDER BY id",
                (run_id, asset_type),
            )
        else:
            rows = conn.execute("SELECT * FROM asset WHERE run_id = ? ORDER BY id", (run_id,))
        return [dict(r) for r in rows]


class ProvenanceRepository:
    def add(self, conn: sqlite3.Connection, asset_id: int, prov: Provenance) -> int | None:
        exists = conn.execute(
            "SELECT 1 FROM provenance WHERE asset_id = ? AND tool = ? "
            "AND IFNULL(raw_ref, '') = IFNULL(?, '')",
            (asset_id, prov.tool, prov.raw_ref),
        ).fetchone()
        if exists:
            return None
        cur = conn.execute(
            "INSERT INTO provenance(asset_id, tool, module, confidence, raw_ref, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (asset_id, prov.tool, prov.module, prov.confidence, prov.raw_ref, _utcnow()),
        )
        return int(cur.lastrowid)


class RelationRepository:
    def upsert(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        src_asset_id: int,
        dst_asset_id: int,
        rel: Relation,
    ) -> int:
        row = conn.execute(
            "SELECT id FROM relation WHERE run_id = ? AND src_asset_id = ? "
            "AND rel_type = ? AND dst_asset_id = ?",
            (run_id, src_asset_id, rel.rel_type, dst_asset_id),
        ).fetchone()
        if row is not None:
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO relation(run_id, src_asset_id, dst_asset_id, rel_type, confidence, source) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (run_id, src_asset_id, dst_asset_id, rel.rel_type, rel.confidence, rel.source),
        )
        return int(cur.lastrowid)

    def list(self, conn: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT * FROM relation WHERE run_id = ? ORDER BY id", (run_id,)
        )
        return [dict(r) for r in rows]


class FindingRepository:
    def add(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        kind: str,
        title: str,
        asset_id: int | None = None,
        severity: str | None = None,
        detail: Any | None = None,
        source: str | None = None,
    ) -> int:
        cur = conn.execute(
            "INSERT INTO finding(run_id, asset_id, kind, severity, title, detail_json, source, created_at) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                asset_id,
                kind,
                severity,
                title,
                json.dumps(detail) if detail is not None else None,
                source,
                _utcnow(),
            ),
        )
        return int(cur.lastrowid)

    def list(self, conn: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
        rows = conn.execute("SELECT * FROM finding WHERE run_id = ? ORDER BY id", (run_id,))
        return [dict(r) for r in rows]

    def delete_by_source(
        self, conn: sqlite3.Connection, run_id: str, sources: list[str]
    ) -> int:
        if not sources:
            return 0
        placeholders = ",".join("?" * len(sources))
        cur = conn.execute(
            f"DELETE FROM finding WHERE run_id = ? AND source IN ({placeholders})",
            (run_id, *sources),
        )
        return cur.rowcount


class ToolRunRepository:
    def record(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        *,
        tool: str,
        module: str | None = None,
        version: str | None = None,
        argv_redacted: str | None = None,
        exit_code: int | None = None,
        status: str | None = None,
        duration_s: float | None = None,
        capture_path: str | None = None,
    ) -> int:
        cur = conn.execute(
            "INSERT INTO tool_run(run_id, module, tool, version, argv, exit_code, status, "
            "duration_s, capture_path, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                module,
                tool,
                version,
                argv_redacted,
                exit_code,
                status,
                duration_s,
                capture_path,
                _utcnow(),
            ),
        )
        return int(cur.lastrowid)

    def list(self, conn: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT * FROM tool_run WHERE run_id = ? ORDER BY id", (run_id,)
        )
        return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Store facade (the API modules use)                                           #
# --------------------------------------------------------------------------- #


class Store:
    """Run-scoped, transactional persistence API composed from repositories."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.runs = RunRepository()
        self.assets = AssetRepository()
        self.provenance = ProvenanceRepository()
        self.relations = RelationRepository()
        self.findings = FindingRepository()
        self.tool_runs = ToolRunRepository()

    @classmethod
    def open(cls, path: str | Path) -> "Store":
        """Open (and initialize) a store at ``path`` (use ``:memory:`` for tests)."""
        db = Database(path)
        db.connect()
        db.initialize()
        return cls(db)

    def close(self) -> None:
        self.db.close()

    # -- run lifecycle ------------------------------------------------------

    def start_run(self, ctx: "Context") -> str:
        scope_json = json.dumps(
            {
                "targets": ctx.scope.targets,
                "in_scope": ctx.scope.in_scope,
                "out_of_scope": ctx.scope.out_of_scope,
            }
        )
        config_hash = hashlib.sha256(
            json.dumps(ctx.config.raw, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

        with self.db.transaction() as conn:
            self.runs.create(
                conn,
                run_id=ctx.run_id,
                domain=ctx.domain.value,
                profile=ctx.profile,
                scope_json=scope_json,
                config_hash=config_hash,
                status="running",
                created_at=ctx.created_at.isoformat(),
            )
            for target in ctx.scope.targets:
                conn.execute(
                    "INSERT INTO target(run_id, value, kind, in_scope) VALUES(?, ?, ?, ?)",
                    (ctx.run_id, target, "domain", 1),
                )
        return ctx.run_id

    def finish_run(self, run_id: str, status: str) -> None:
        with self.db.transaction() as conn:
            self.runs.set_status(conn, run_id, status, _utcnow())

    # -- writes -------------------------------------------------------------

    def record_tool_run(self, run_id: str, **kwargs: Any) -> int:
        with self.db.transaction() as conn:
            return self.tool_runs.record(conn, run_id, **kwargs)

    def add_finding(self, run_id: str, **kwargs: Any) -> int:
        with self.db.transaction() as conn:
            return self.findings.add(conn, run_id, **kwargs)

    def clear_findings(self, run_id: str, sources: list[str]) -> int:
        """Delete findings produced by the given sources (for re-analysis)."""
        with self.db.transaction() as conn:
            return self.findings.delete_by_source(conn, run_id, sources)

    def persist_normalization(self, run_id: str, result: Any) -> dict[str, int]:
        """Persist a NormalizationResult: upsert entities (+provenance) and relations."""
        counts = {"assets": 0, "provenance": 0, "relations": 0}
        with self.db.transaction() as conn:
            id_map: dict[tuple[str, str], int] = {}
            for entity in result.entities:
                asset_id = self.assets.upsert(conn, run_id, entity)
                id_map[(entity.asset_type, entity.canonical_key)] = asset_id
                counts["assets"] += 1
                for prov in entity.sources:
                    if self.provenance.add(conn, asset_id, prov) is not None:
                        counts["provenance"] += 1

            for rel in result.relations:
                src = self._resolve_asset(conn, id_map, run_id, rel.src_type, rel.src_key)
                dst = self._resolve_asset(conn, id_map, run_id, rel.dst_type, rel.dst_key)
                if src is not None and dst is not None:
                    self.relations.upsert(conn, run_id, src, dst, rel)
                    counts["relations"] += 1
        return counts

    def _resolve_asset(
        self,
        conn: sqlite3.Connection,
        id_map: dict[tuple[str, str], int],
        run_id: str,
        asset_type: str,
        key: str,
    ) -> int | None:
        ckey = canonical_key(asset_type, key)
        if (asset_type, ckey) in id_map:
            return id_map[(asset_type, ckey)]
        return self.assets.find_id(conn, run_id, asset_type, ckey)

    # -- reads --------------------------------------------------------------

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        return self.runs.get(self.db.conn, run_id)

    def list_assets(self, run_id: str, asset_type: str | None = None) -> list[dict[str, Any]]:
        return self.assets.list(self.db.conn, run_id, asset_type)

    def list_relations(self, run_id: str) -> list[dict[str, Any]]:
        return self.relations.list(self.db.conn, run_id)

    def list_tool_runs(self, run_id: str) -> list[dict[str, Any]]:
        return self.tool_runs.list(self.db.conn, run_id)

    def list_findings(self, run_id: str) -> list[dict[str, Any]]:
        return self.findings.list(self.db.conn, run_id)
