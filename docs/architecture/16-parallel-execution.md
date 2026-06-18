# 16 — Future Parallel Execution

[← 15 Output Management](15-output-management.md) · [Index](../ARCHITECTURE.md) · Next: [17 Distributed Execution →](17-distributed-execution.md)

The seams are already present; v1 simply runs the DAG sequentially.

- **The DAG already encodes parallelism:** sibling stages (no edge between them, see [05 Pipeline](05-pipeline.md)) are provably independent and can run concurrently. The Orchestrator's scheduler interface is designed to dispatch ready-nodes to a pool; v1 ships a sequential scheduler, a future version ships a concurrent one — *modules don't change*.
- **CommandExecutor concurrency controls** (global and per-tool limits, rate limiting) are part of its design surface ([08](08-engine-services.md)) so parallelism stays polite and in-scope.
- **No shared mutable state** ([Context](07-context-object.md) core is read-only; data flows through DB/graph) means concurrent modules don't race on memory.
- **Idempotent upserts** (unique natural-key index, [09 §9.5](09-database.md)) make concurrent writes safe and reruns deterministic.

## Granularity options (designed-for, not built)

- **Stage-level parallelism:** run sibling stages together.
- **Target-level parallelism:** fan out the same stage across many subdomains.

Both are scheduler concerns only — no module, parser, or schema change required.
