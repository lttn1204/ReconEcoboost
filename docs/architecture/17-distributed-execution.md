# 17 — Future Distributed Execution

[← 16 Parallel Execution](16-parallel-execution.md) · [Index](../ARCHITECTURE.md) · Next: [18 Folder Structure →](18-folder-structure.md)

- **Serializable Context core** ([07](07-context-object.md): identity + scope + config) ships to workers; results merge through the shared store.
- **Backend swap to Postgres** (via the repository interface, [09](09-database.md)) gives concurrent multi-worker writes and a shared graph.
- **A queue/broker seam** sits behind the scheduler interface: the Orchestrator enqueues ready DAG nodes; workers pull, execute ([CommandExecutor](08-engine-services.md) possibly in a container/remote host), and persist. The Orchestrator becomes a coordinator.
- **Containerized/remote execution** is a CommandExecutor implementation swap — modules are unaffected.
- **Run partitioning by `run_id`** enables horizontal scaling and clean isolation between engagements.

None of this lands in v1; the architecture only guarantees these can be added **without reshaping modules, schema spine, or the AI boundary.**
