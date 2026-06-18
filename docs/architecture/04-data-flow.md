# 04 — Data Flow

[← 03 Component Diagram](03-component-diagram.md) · [Index](../ARCHITECTURE.md) · Next: [05 Pipeline →](05-pipeline.md)

The canonical path a single fact travels, from tool invocation to AI insight:

```
 target (scope)
     │
     ▼
[Module.run(ctx)]
     │  asks ToolManager: "where is subfinder, is it ok?"
     ▼
[ToolManager] ── binary path + version ──▶ [Module]
     │
     ▼
[Module] builds argv (NO shell string) ─▶ [CommandExecutor]
     │                                          │ spawn, timeout, retry
     │                                          ▼
     │                                   raw stdout / stderr / exit code / duration
     │◀─────────────────────────────────────────┘
     ▼
[Parser.parse(raw)] ──▶ list[ParsedRecord]   (tool-specific shape → typed records)
     │
     ▼
[Normalizer] ──▶ list[CanonicalEntity] + list[Relation]   (deduped, schema-stable)
     │
     ├───────────────▶ [DB Repositories] ──▶ SQLite (upsert by natural key)
     │
     └───────────────▶ [Graph Builder] ──▶ Knowledge Graph (nodes + edges)
     │
     ▼
[Context] updated with handles/IDs of what was produced (not the raw blobs)
     │
     ▼
   ... later stages read prior entities via repositories / graph queries ...
     │
     ▼
[Analysis Module] ──▶ assembles a *curated, structured* view ──▶ [Prompt Manager]
     │                                                               │ renders template
     ▼                                                               ▼
[AI Provider Abstraction] ──▶ LLM ──▶ structured response (summary / classification / plan)
     │
     ▼
[DB + Graph] store AI artifacts as first-class records (findings, plans, hypotheses)
     │
     ▼
[Output writer] ──▶ JSON / Markdown / HTML report
```

## The hard rule, visualized

Raw stdout exits the [CommandExecutor](08-engine-services.md) and **dies at the Parser**. It is never carried forward, never logged into the graph as a blob, and never handed to the LLM. The full justification lives in [15 Output Management](15-output-management.md).
