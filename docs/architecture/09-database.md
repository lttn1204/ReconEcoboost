# 09 — Database Layer

[← 08 Engine Services](08-engine-services.md) · [Index](../ARCHITECTURE.md) · Next: [10 Knowledge Graph →](10-knowledge-graph.md)

> Per the project brief: **design described, no SQL generated.**

## 9.1 Engine choice

**SQLite for v1** (single file, zero-ops, transactional, excellent for a single-operator laptop tool), accessed exclusively through a **repository layer** so the rest of the code never sees SQL or the driver.

### Design decision — SQLite now, abstract the repository

- **Advantages:** no server, portable per-engagement DB file, ACID, fast for the data volumes a single run produces.
- **Disadvantages:** weak concurrent-write story; no native graph or rich JSON querying (acceptable — graph is layered on top, [10](10-knowledge-graph.md)).
- **Future extensibility:** because access is via repositories returning domain objects, swapping to PostgreSQL (concurrent distributed workers, JSONB, richer indexing) is a backend change behind the same interface ([17](17-distributed-execution.md)).
- **Alternatives:** Postgres from day one (overkill for v1, ops burden); document store (loses relational integrity we want for scope/provenance); pure files (no querying).

## 9.2 Canonical entity taxonomy (the heart of the schema)

The schema is built around **domain-agnostic core tables** plus **domain-specific detail tables**, so new domains add tables without reshaping the core.

**Core, domain-agnostic tables:**
- `run` — one row per execution: id, domain, scope snapshot, config hash, tool versions, timestamps, status.
- `target` — the scope roots for a run (domain/IP/CIDR/repo, with in/out-of-scope flag).
- `asset` — the universal node table. A polymorphic record with `asset_type` (subdomain, host, url, endpoint, service, technology, credential-surface, artifact, …), a canonical natural key, first/last-seen, and a `run_id`. This is the single spine the graph and AI build on.
- `provenance` — which tool/module/run produced or confirmed a given asset (many-to-one to `asset`). Captures source, confidence, and the raw-capture reference (path on disk), **not** the raw blob itself.
- `finding` — AI- or rule-derived insights (summaries, classifications, hypotheses, attack-plan items) attached to assets, typed and severity-tagged.
- `relation` — typed, directed edges between assets (the graph's storage form, [10](10-knowledge-graph.md)).
- `tool_run` — one row per CommandExecutor invocation: tool, version, argv (redacted), exit, duration, capture path, status. The execution audit log.

**Domain-specific detail tables (1:1 extensions of `asset`):**
- Web: `web_host` (scheme, port, status code, title, server header, TLS info), `web_url` (path, method, params, content-type, length), `web_technology` (name, version, category, cpe).
- Later domains add their own (`network_service`, `ad_principal`, `cloud_resource`, `k8s_object`, …) — **never altering core tables**.

## 9.3 Relationships

- `run 1—N target`, `run 1—N asset`, `run 1—N tool_run`.
- `asset 1—N provenance` (a fact corroborated by multiple tools).
- `asset 1—1 <domain detail>` (subtype extension).
- `asset N—N asset` via `relation` (the graph).
- `asset 1—N finding`.

## 9.4 Normalization strategy

- **Third-normal-form core** for the relational truth: assets are deduplicated by natural key; provenance is factored out so corroboration doesn't duplicate the asset; domain attributes live in subtype tables, not as nullable columns on a wide universal table.
- **Deliberate denormalization at the edges:** a small number of cached/rollup columns (e.g. last-seen, counts) and JSON columns for genuinely schema-less tool extras (raw key/values that don't warrant a column). The rule: *structured where we query it, JSON where we only store it.*

## 9.5 Indexing

- Unique index on `asset(run_id, asset_type, canonical_key)` — enforces dedupe and powers upserts.
- Index on `asset(asset_type)` and `asset(run_id)` for stage queries ("all `url` for this run").
- Indexes on `relation(src_asset_id)` and `relation(dst_asset_id)` for graph traversal in both directions.
- Index on `provenance(asset_id)` and `tool_run(run_id)`.
- Index on `finding(asset_id, severity)` for report generation.

## 9.6 Future scalability

- Repository interface lets the backend move to Postgres (concurrent workers, partitioning by `run_id`, JSONB for extras, GIN indexes).
- `run_id` partition key makes per-engagement sharding and archival natural.
- The asset/relation spine maps cleanly onto a dedicated graph DB later ([10](10-knowledge-graph.md)) if traversal needs outgrow SQL recursive CTEs.
