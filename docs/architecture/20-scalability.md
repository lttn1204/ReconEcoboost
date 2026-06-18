# 20 — Scalability Considerations

[← 19 Decision Ledger](19-decision-ledger.md) · [Index](../ARCHITECTURE.md) · Next: [21 Roadmap →](21-roadmap.md)

- **Data volume:** `run_id` partitioning + indexed natural keys keep per-run queries fast; archival is per-run-directory + per-run DB rows. See [09 Database](09-database.md).
- **Execution:** DAG-encoded parallelism → scheduler swap → queue/worker distribution, all behind stable interfaces. See [16 Parallel](16-parallel-execution.md), [17 Distributed](17-distributed-execution.md).
- **Storage:** repository abstraction → Postgres → (if needed) dedicated graph DB. See [10 Knowledge Graph](10-knowledge-graph.md).
- **AI cost/throughput:** provider base handles caching, budgeting, and multi-model routing; curated subgraphs (not raw data) keep token use minimal. See [11 AI Abstraction](11-ai-abstraction.md), [15 Output Management](15-output-management.md).
- **Domain growth:** nine domains add modules + subtype tables + prompts; core, engine, orchestration, AI boundary stay fixed.
