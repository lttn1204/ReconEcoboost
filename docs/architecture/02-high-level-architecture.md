# 02 — High-Level Architecture

[← 01 Design Principles](01-design-principles.md) · [Index](../ARCHITECTURE.md) · Next: [03 Component Diagram →](03-component-diagram.md)

```
                       ┌─────────────────────────────────────────────┐
                       │                   CLI / API                  │
                       │        (entry point, run lifecycle)          │
                       └───────────────────────┬─────────────────────┘
                                               │ builds Context, loads config
                                               ▼
                       ┌─────────────────────────────────────────────┐
                       │                ORCHESTRATOR                   │
                       │   (resolves pipeline DAG, schedules stages)   │
                       └───────────────────────┬─────────────────────┘
                                               │ runs modules in dependency order
            ┌──────────────────────────────────┼──────────────────────────────────┐
            ▼                                   ▼                                    ▼
   ┌─────────────────┐                 ┌─────────────────┐                 ┌─────────────────┐
   │  RECON MODULES  │                 │  RECON MODULES   │                 │  ANALYSIS       │
   │  (subfinder,    │  ───────────▶   │  (httpx, katana, │  ───────────▶   │  MODULES        │
   │   ...)          │                 │   gau, ffuf, ww) │                 │  (AI summary,   │
   └────────┬────────┘                 └────────┬─────────┘                 │   attack plan)  │
            │ uses                               │ uses                     └────────┬────────┘
            ▼                                    ▼                                   │ uses
   ┌───────────────────────────────────────────────────────┐                       ▼
   │     SHARED SERVICES (the "engine" toolbelt)            │              ┌──────────────────┐
   │  CommandExecutor · ToolManager · Parser registry ·     │              │  AI PROVIDER     │
   │  Normalizer · Config · Logging · Output writer         │              │  ABSTRACTION     │
   └───────────────────────────┬───────────────────────────┘              └──────────────────┘
                               │ persists                                          ▲
                               ▼                                                   │ reads facts
   ┌───────────────────────────────────────────────────────────────────────────────────────┐
   │                          PERSISTENCE & KNOWLEDGE LAYER                                   │
   │   Database (SQLite, normalized)   ◀────────▶   Knowledge Graph (entities + relations)    │
   └───────────────────────────────────────────────────────────────────────────────────────┘
```

## Layered view

Strict dependency direction — upper depends on lower, never the reverse:

```
┌──────────────────────────────────────────────┐
│  Presentation:  CLI / (future) REST / TUI     │
├──────────────────────────────────────────────┤
│  Orchestration: Pipeline planner + scheduler  │
├──────────────────────────────────────────────┤
│  Domain Modules: recon + analysis plugins     │
├──────────────────────────────────────────────┤
│  Engine Services: Executor, ToolManager,      │
│                   Parser, Normalizer, AI       │
├──────────────────────────────────────────────┤
│  Persistence:   DB repositories + Graph        │
├──────────────────────────────────────────────┤
│  Foundation:    Config, Logging, Context,      │
│                 Models/Schemas, Errors         │
└──────────────────────────────────────────────┘
```

The Foundation layer has zero dependencies on anything above it. Modules depend on Engine Services and Foundation, never on each other.

## CLI Entry Point

The CLI is the presentation layer and run-lifecycle owner: it parses arguments and the selected pipeline profile, loads and merges configuration ([13](13-configuration.md)), constructs the [Context](07-context-object.md), creates the per-run workspace ([15](15-output-management.md)), hands control to the Orchestrator, and finalizes the run record at the end. It contains no recon logic. A future REST API or TUI is an additional presentation surface over the same Orchestrator and Context, requiring no change below this layer.
