# 15 — Output Management

[← 14 Logging](14-logging.md) · [Index](../ARCHITECTURE.md) · Next: [16 Parallel Execution →](16-parallel-execution.md)

A dedicated **Output writer** produces deliverables from the durable store ([DB](09-database.md) + [graph](10-knowledge-graph.md)), decoupled from execution:

- **Formats:** machine JSON (full normalized dataset), Markdown report (human summary + AI findings + attack plan), and a future HTML report; raw captures and screenshots remain as referenced artifacts in the run workspace.
- **Run workspace layout:** each run gets an isolated directory containing raw captures, artifacts, the run log, and rendered reports — making a run self-contained, archivable, and shareable.
- **Why outputs derive from the store, not from module return values:** reports are reproducible and re-renderable without re-running tools; new report formats are added without touching modules.

## The Output Pipeline (the hard rule)

```
Raw Tool Output → Parser → Normalized JSON → Database → Knowledge Graph → AI
```

Raw stdout never goes straight to the LLM because:

- it's **noisy and token-expensive** (banners, progress, ANSI, duplicates) — wasting context and money;
- it's **unstructured and ambiguous** — the model would re-parse what a deterministic parser does reliably, hallucinating structure;
- it's **unsafe** — raw output can contain secrets/PII and even prompt-injection payloads (a malicious page title or header) that would reach the model unfiltered;
- it's **inconsistent** across tools, so prompts couldn't be stable;
- it **breaks provenance** — normalized entities carry source/confidence; raw text doesn't.

Sending curated, normalized, deduplicated structure makes AI output accurate, cheap, reproducible, and auditable. The text→structure boundary is the [Parser](08-engine-services.md); raw stdout dies there ([04 Data Flow](04-data-flow.md)).
