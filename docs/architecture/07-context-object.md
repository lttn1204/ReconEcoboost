# 07 — Context Object

[← 06 Module System](06-module-system.md) · [Index](../ARCHITECTURE.md) · Next: [08 Engine Services →](08-engine-services.md)

## 7.1 What it contains

The `Context` is the explicit, per-run state envelope threaded into every `Module.run(ctx)`:

- **Identity:** `run_id`, `created_at`, `domain`, operator/profile name.
- **Scope:** the targets and in-scope / out-of-scope rules (roots, allowed domains, CIDRs, exclusions). Modules consult scope before acting.
- **Resolved config:** typed, already-merged config (tools, pipeline, wordlists, ai — see [13](13-configuration.md)) — read-only to modules.
- **Service handles:** references to [CommandExecutor, ToolManager](08-engine-services.md), repositories, graph, logger, output writer, AI provider. Modules receive their dependencies; they do not import singletons.
- **Run-scoped workspace:** path to this run's output directory (raw captures, artifacts, logs — see [15](15-output-management.md)).
- **Result ledger:** per-module `ModuleResult` records (status, counts, timings, errors) — the audit trail of the run.
- **Cursors, not blobs:** Context holds *references/IDs* to produced entities (or nothing, deferring to repositories). It deliberately does **not** accumulate raw outputs or full entity sets in memory.

## 7.2 Lifecycle

Created by the CLI/entry point at run start → populated with resolved config and service handles → passed read-mostly through each module → finalized and persisted as a run record at end. One Context per run; never reused across runs.

## 7.3 Ownership & mutation strategy

- **Read-only core:** identity, scope, config, and service handles are immutable after construction.
- **Append-only ledger:** modules append their `ModuleResult`; they never rewrite another module's entry.
- **No shared mutable scratch space.** Cross-module data passes through the [database/graph](09-database.md), not through mutable Context fields. If module B needs module A's URLs, B queries the repository for `url` entities of this `run_id` — it does not read a `ctx.urls` list A mutated.

## 7.4 Design decision — explicit Context over global state / singletons

- **Rationale:** Testability, concurrency-readiness, and traceability. A function's dependencies are visible in its signature.
- **Advantages:** Trivial to unit-test a module with a fake Context; safe to run multiple Contexts concurrently in one process (future parallelism, [16](16-parallel-execution.md)); no spooky action at a distance.
- **Disadvantages:** Slightly more verbose; Context can become a "god object" if undisciplined (mitigated by the read-mostly + data-through-DB rules).
- **Future extensibility:** A distributed run ([17](17-distributed-execution.md)) serializes the read-only core and ships it to workers; the append-only ledger merges cleanly.
- **Alternatives:** Global singleton config/registry (simple, but untestable and concurrency-hostile); dependency-injection container (powerful, but more machinery than a CLI needs in v1).
