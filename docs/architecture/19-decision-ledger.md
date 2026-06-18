# 19 — Consolidated Design-Decision Ledger

[← 18 Folder Structure](18-folder-structure.md) · [Index](../ARCHITECTURE.md) · Next: [20 Scalability →](20-scalability.md)

| # | Decision | Rationale | Key Disadvantage | Primary Alternative | Detail |
|---|---|---|---|---|---|
| 1 | AI reasons, Engine executes | Safety, determinism, auditability | More layers between model and action | Let AI call tools (rejected: unsafe) | [01](01-design-principles.md) |
| 2 | Plugin modules + declarative DAG | Zero-edit extensibility | Execution order not linear in source | Hard-coded sequence | [06](06-module-system.md) |
| 3 | Explicit Context, no globals | Testable, concurrency-ready | Verbosity / god-object risk | Singletons / DI container | [07](07-context-object.md) |
| 4 | Central CommandExecutor | Uniform timeout/retry/log/security | Thin overhead | Direct subprocess (rejected) | [08](08-engine-services.md) |
| 5 | Central ToolManager | One preflight, reproducible versions | Per-tool version parsing brittle | Per-module discovery | [08](08-engine-services.md) |
| 6 | Parser ≠ Normalizer split | Tool-coupling vs domain-coupling isolated | Two layers to traverse | One combined parser | [08](08-engine-services.md) |
| 7 | SQLite + repository layer | Zero-ops, ACID, portable; swappable | Weak concurrent writes | Postgres day-one / files | [09](09-database.md) |
| 8 | Asset/relation spine + subtype tables | New domains add tables, not reshape core | Polymorphic asset needs discipline | Wide table / per-domain silos | [09](09-database.md) |
| 9 | Graph-on-SQL, graph-DB-ready | No new infra; clean upgrade | SQL traversal clumsier | Neo4j day-one | [10](10-knowledge-graph.md) |
| 10 | Thin AI adapters + structured contract | Provider independence, offline mode | Lowest-common-denominator risk | Hardcode one SDK / heavy framework | [11](11-ai-abstraction.md) |
| 11 | External Markdown prompts | Fast iteration, non-dev editable, reproducible | Template/code drift risk | Inline prompts / prompt SaaS | [12](12-prompt-management.md) |
| 12 | Layered concern-split YAML config | Clear ownership, early validation | More files | Single file / env-only | [13](13-configuration.md) |
| 13 | Raw output dies at Parser | Cost, accuracy, security, provenance | — | Raw → LLM (rejected) | [15](15-output-management.md) |
| 14 | Sequential now, parallel/distributed seams | Ship simple, scale without reshape | Unused abstraction surface | Build distributed now (premature) | [16](16-parallel-execution.md), [17](17-distributed-execution.md) |
