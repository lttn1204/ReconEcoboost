# 03 — Component Diagram

[← 02 High-Level Architecture](02-high-level-architecture.md) · [Index](../ARCHITECTURE.md) · Next: [04 Data Flow →](04-data-flow.md)

```
                                  ┌────────────────────┐
                                  │      Config        │  tools.yaml / pipeline.yaml
                                  │      Loader        │  wordlists.yaml / ai.yaml
                                  └─────────┬──────────┘
                                            │ typed config objects
                                            ▼
┌────────────────┐   discovers    ┌────────────────────┐   threads    ┌────────────────────┐
│ Module Registry│ ─────────────▶ │   Orchestrator     │ ───────────▶ │     Context        │
│ (plugin loader)│                │   (DAG runner)     │              │ (shared run state) │
└────────────────┘                └─────────┬──────────┘              └────────────────────┘
                                            │ invokes .run(ctx) per module
                                            ▼
                           ┌──────────────────────────────────┐
                           │            Module (ABC)           │
                           │  declares: name, stage, requires, │
                           │  produces, tool, parser           │
                           └───┬───────────────┬───────────┬───┘
                  uses tool    │     uses      │   emits   │
                               ▼               ▼           ▼
                  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
                  │  ToolManager   │  │ CommandExecutor│  │   Parser       │
                  │ (binary lookup,│  │ (run/timeout/  │  │ (text→records) │
                  │  version, deps)│  │  retry/capture)│  └───────┬────────┘
                  └────────────────┘  └────────────────┘          │
                                                                  ▼
                                                        ┌────────────────┐
                                                        │   Normalizer   │
                                                        │ (records→canon │
                                                        │  entities)     │
                                                        └───────┬────────┘
                                                                ▼
                              ┌──────────────────┐    ┌──────────────────┐
                              │  DB Repositories │◀──▶│  Graph Builder   │
                              └────────┬─────────┘    └────────┬─────────┘
                                       ▼                       ▼
                              ┌──────────────────┐    ┌──────────────────┐
                              │   SQLite store   │    │ Knowledge Graph  │
                              └──────────────────┘    └──────────────────┘
                                                                │
                                                                ▼
                                                       ┌──────────────────┐
                                                       │ AI Provider Abs. │
                                                       │ + Prompt Manager │
                                                       └──────────────────┘
```

Related detail: [06 Module System](06-module-system.md), [08 Engine Services](08-engine-services.md), [09 Database](09-database.md), [10 Knowledge Graph](10-knowledge-graph.md), [11 AI Abstraction](11-ai-abstraction.md).
