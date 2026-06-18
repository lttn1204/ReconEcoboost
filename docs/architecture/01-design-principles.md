# 01 — Design Principles (the non-negotiables)

[← Index](../ARCHITECTURE.md) · Next: [02 High-Level Architecture →](02-high-level-architecture.md)

The guiding invariant of the whole system:

> **The AI reasons. The Engine executes. Neither does the other's job.**

Every design choice in this document set defends that boundary.

1. **Separation of reasoning and execution.** The LLM never spawns a process, never reads raw stdout, never decides shell arguments at runtime. It receives *normalized, structured facts* and emits *structured intent* (plans, classifications, hypotheses). A compromised or hallucinating model can therefore never directly run a tool.
2. **Everything is a plugin.** Each recon stage is a self-contained, independently replaceable module discovered at runtime. Adding a stage never edits an existing stage. See [06 Module System](06-module-system.md).
3. **One domain today, nine domains tomorrow.** Web is the first *domain*, not the *only* domain. The pipeline, context, storage, and graph are domain-agnostic; "web-ness" lives only inside web modules and web entity types.
4. **Structured data is the contract.** Tools speak text; the rest of the system speaks normalized JSON / typed records. The boundary where text becomes structure (the Parser) is the most carefully guarded layer. See [08 Engine Services](08-engine-services.md).
5. **Determinism where possible, intelligence where needed.** Orchestration, execution, parsing, and storage are deterministic and testable. Only analysis and planning are probabilistic.
6. **No hidden global state.** A single explicit `Context` object is threaded through the pipeline. No module reaches for a global singleton to discover what scan it's part of. See [07 Context Object](07-context-object.md).
7. **Fail loud, degrade gracefully.** A tool crash fails *that module*, recorded as a typed error, and the pipeline continues with what it has. One broken stage never aborts the run.
8. **Local-first, scale-later.** v1 runs on one laptop against SQLite with sequential execution. The seams for parallel ([16](16-parallel-execution.md)) and distributed ([17](17-distributed-execution.md)) execution are designed in now but not built now.
