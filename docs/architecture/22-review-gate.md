# 22 — Review Gate

[← 21 Roadmap](21-roadmap.md) · [Index](../ARCHITECTURE.md)

> **Status: RESOLVED (2026-06-16).** All five questions answered and locked. Implementation is unblocked.

| # | Question | Decision |
|---|---|---|
| 1 | **Taxonomy** — core `asset` + subtype model ([09](09-database.md)) | ✅ Approved as designed. |
| 2 | **Graph-on-SQL vs. graph DB** ([10](10-knowledge-graph.md)) for v1 | ✅ Start on the **SQLite-backed graph**. |
| 3 | **Default AI provider** ([11](11-ai-abstraction.md)) | ✅ **Claude** is the default provider. (Provider abstraction is retained; local/Ollama remains a future adapter, not a v1 requirement.) |
| 4 | **Config split** ([13](13-configuration.md)) | ✅ Keep the four-file design (tools/pipeline/wordlists/ai). |
| 5 | **Scope enforcement** | ✅ Confirmed — scope checks live in [Context](07-context-object.md) + [CommandExecutor](08-engine-services.md) as the chokepoint. |

### Original questions (for the record)

1. **Taxonomy** — does the core `asset` + subtype model ([09](09-database.md)) match how you think about cross-domain recon entities?
2. **Graph-on-SQL vs. graph DB** ([10](10-knowledge-graph.md)) for v1 — comfortable starting on SQLite-backed graph?
3. **Default AI provider** ([11](11-ai-abstraction.md)) — Claude primary with Ollama/local fallback acceptable, or must v1 be local-only for engagement confidentiality?
4. **Config split** ([13](13-configuration.md)) — four files (tools/pipeline/wordlists/ai) right, or do you want them merged/split differently?
5. **Scope enforcement** — confirm scope checks belong in [Context](07-context-object.md) + [CommandExecutor](08-engine-services.md) as the chokepoint.

## Proposed first build slice (on approval)

A single end-to-end vertical before fanning out:

```
Foundation (core + config + logging)
   → engine (CommandExecutor + ToolManager + one parser)
      → one vertical module (asset_discovery with subfinder)
         → persistence spine (asset/provenance/tool_run + repository)
```

This proves the whole pipeline on one stage end-to-end, validating the Context, Executor, Parser, Normalizer, and DB contracts before any second module exists.
