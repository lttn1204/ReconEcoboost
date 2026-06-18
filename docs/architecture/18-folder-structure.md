# 18 — Recommended Folder Structure

[← 17 Distributed Execution](17-distributed-execution.md) · [Index](../ARCHITECTURE.md) · Next: [19 Decision Ledger →](19-decision-ledger.md)

> Layout proposal only — no files are generated in this design phase.

```
ReconEcoboost/
├── docs/
│   ├── ARCHITECTURE.md              # index
│   └── architecture/                # this document set (one file per component)
├── prompts/                         # external, versioned prompt templates ([12])
│   └── web/
│       ├── summarize.md
│       ├── classify.md
│       └── attack_plan.md
├── config/                          # shipped default configs (user copies/overrides) ([13])
│   ├── tools.yaml
│   ├── pipeline.yaml
│   ├── wordlists.yaml
│   └── ai.yaml
├── src/reconecoboost/               # the package (import root)
│   ├── cli/                         # entry point, argument parsing, run lifecycle ([02])
│   ├── core/                        # Foundation: Context, errors, base models/schemas, taxonomy ([07])
│   ├── config/                      # config loading, merging, typed config objects ([13])
│   ├── orchestration/              # module registry, DAG planner, scheduler(s) ([05],[06])
│   ├── engine/                      # CommandExecutor, ToolManager, parser base, normalizer ([08])
│   ├── modules/                     # the plugins, by domain ([06])
│   │   ├── web/                     # v1: asset_discovery, alive, crawl, hist_urls,
│   │   │                            #     dir_brute, tech_fp, screenshot, normalize
│   │   ├── api/                     # (future) — empty placeholder, no core change to add
│   │   ├── host/                    # (future)
│   │   ├── network/                 # (future)
│   │   ├── ad/  cloud/  k8s/        # (future)
│   │   └── container/  mobile/      # (future)
│   ├── analysis/                    # AI-facing modules: summary, classification, attack planning
│   ├── ai/                          # AIProvider ABC + adapters (claude/openai/gemini/ollama/local) ([11])
│   ├── prompts/                     # Prompt Manager (loads/renders prompts/ tree) ([12])
│   ├── persistence/                 # repositories, DB session/migrations runner, graph builder/queries ([09])
│   ├── graph/                       # knowledge-graph interface + SQL-backed impl (graph-DB-ready) ([10])
│   ├── output/                      # report/JSON/HTML writers, run-workspace management ([15])
│   └── logging/                     # structured logging setup, redaction, correlation ([14])
├── tests/                           # mirrors src/: unit (fake Context/Executor/Provider) + fixtures
│   └── fixtures/                    # captured raw tool outputs for parser tests
└── runs/                            # per-run workspaces (raw captures, artifacts, logs, reports)
```

## Directory purposes (why each exists)

- `core/` — the dependency-free Foundation (Context, taxonomy, errors). Everything imports it; it imports nothing internal. Protects the layering.
- `orchestration/` — the only place that knows execution *order*; isolates the DAG/scheduler so parallel/distributed swaps are contained here.
- `engine/` — the deterministic "muscle" (exec, tools, parse, normalize). The security- and reliability-critical chokepoints live here.
- `modules/` + `analysis/` — the swappable plugins; the only place new recon capability is added. Split by domain so domains grow independently.
- `ai/` + `prompts/` (code) + `prompts/` (templates) — the reasoning boundary, fully isolated and provider-agnostic.
- `persistence/` + `graph/` — durable truth and its relational/graph access, behind repository/graph interfaces for backend swaps.
- `output/`, `logging/`, `config/` — cross-cutting services with clear single responsibilities.
- `runs/` — durable, self-contained per-engagement evidence.
