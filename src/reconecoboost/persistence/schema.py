"""SQLite schema (DDL).

Implements the core, domain-agnostic spine from architecture doc 09: ``run`` /
``target`` / ``asset`` / ``provenance`` / ``relation`` / ``finding`` /
``tool_run``. Domain subtype tables (``web_host`` etc.) are added alongside their
recon modules and extend ``asset`` 1:1 without altering the core.

The ``asset`` natural-key uniqueness ``(run_id, asset_type, canonical_key)``
enforces dedupe and powers upserts. The ``relation`` table is the storage form
of the knowledge graph (the SQLite-backed graph layer, doc 10, queries it).
"""

from __future__ import annotations

SCHEMA = """
CREATE TABLE IF NOT EXISTS run (
    id           TEXT PRIMARY KEY,
    domain       TEXT NOT NULL,
    profile      TEXT,
    scope_json   TEXT,
    config_hash  TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL,
    finished_at  TEXT
);

CREATE TABLE IF NOT EXISTS target (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    value     TEXT NOT NULL,
    kind      TEXT,
    in_scope  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS asset (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    asset_type      TEXT NOT NULL,
    canonical_key   TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}',
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    UNIQUE (run_id, asset_type, canonical_key)
);
CREATE INDEX IF NOT EXISTS idx_asset_run    ON asset(run_id);
CREATE INDEX IF NOT EXISTS idx_asset_type   ON asset(asset_type);

CREATE TABLE IF NOT EXISTS provenance (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id    INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    tool        TEXT NOT NULL,
    module      TEXT,
    confidence  REAL NOT NULL DEFAULT 1.0,
    raw_ref     TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provenance_asset ON provenance(asset_id);

CREATE TABLE IF NOT EXISTS relation (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    src_asset_id  INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    dst_asset_id  INTEGER NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
    rel_type      TEXT NOT NULL,
    confidence    REAL NOT NULL DEFAULT 1.0,
    source        TEXT,
    UNIQUE (run_id, src_asset_id, rel_type, dst_asset_id)
);
CREATE INDEX IF NOT EXISTS idx_relation_src ON relation(src_asset_id);
CREATE INDEX IF NOT EXISTS idx_relation_dst ON relation(dst_asset_id);

CREATE TABLE IF NOT EXISTS finding (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id       TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    asset_id     INTEGER REFERENCES asset(id) ON DELETE SET NULL,
    kind         TEXT NOT NULL,
    severity     TEXT,
    title        TEXT NOT NULL,
    detail_json  TEXT,
    source       TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_asset ON finding(asset_id, severity);
CREATE INDEX IF NOT EXISTS idx_finding_run   ON finding(run_id);

CREATE TABLE IF NOT EXISTS tool_run (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL REFERENCES run(id) ON DELETE CASCADE,
    module        TEXT,
    tool          TEXT NOT NULL,
    version       TEXT,
    argv          TEXT,
    exit_code     INTEGER,
    status        TEXT,
    duration_s    REAL,
    capture_path  TEXT,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_run_run ON tool_run(run_id);
"""
