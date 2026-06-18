# 05 — Pipeline (v1 Web stages)

[← 04 Data Flow](04-data-flow.md) · [Index](../ARCHITECTURE.md) · Next: [06 Module System →](06-module-system.md)

Stages form a **DAG**, not a fixed list. Edges are declared by each module's `requires`/`produces` (see [06 Module System](06-module-system.md)), and the Orchestrator topologically sorts them.

```
                         ┌──────────────────────┐
                         │   asset_discovery     │  subfinder
                         │   produces: subdomain │
                         └───────────┬──────────┘
                                     ▼
                         ┌──────────────────────┐
                         │   alive_detection     │  httpx
                         │   requires: subdomain │
                         │   produces: host(http)│
                         └───────────┬──────────┘
              ┌──────────────────────┼──────────────────────┬───────────────────┐
              ▼                      ▼                      ▼                   ▼
   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │   crawling        │  │ historical_urls   │  │ tech_fingerprint  │  │   screenshot      │
   │   katana          │  │ gau               │  │ whatweb           │  │ (future:gowitness)│
   │ req: host(http)   │  │ req: host(http)   │  │ req: host(http)   │  │ req: host(http)   │
   │ prod: url,endpoint│  │ prod: url         │  │ prod: technology  │  │ prod: artifact    │
   └─────────┬────────┘  └─────────┬────────┘  └──────────────────┘  └──────────────────┘
             └────────────┬────────┘
                          ▼
              ┌──────────────────────┐
              │  dir_bruteforce       │  ffuf
              │  req: host(http), url │
              │  prod: url(status)    │
              └───────────┬──────────┘
                          ▼
              ┌──────────────────────┐
              │   normalization       │  (cross-tool dedupe, canonical merge)
              │   req: url,endpoint,  │
              │        technology     │
              └───────────┬──────────┘
                          ▼
              ┌──────────────────────┐
              │   ai_summary          │  reads graph slice → summarize.md
              └───────────┬──────────┘
                          ▼
              ┌──────────────────────┐
              │   ai_attack_planning  │  reads graph + findings → attack_plan.md
              └──────────────────────┘
```

## Modularity guarantee

Every recon stage is independently replaceable. Stages with no dependency edge between them (crawling, historical_urls, tech_fingerprint, screenshot) are **siblings** — explicitly parallelizable later ([16](16-parallel-execution.md)) without any code change to them.

Adding a new stage (e.g. `port_scan` with naabu, or `nuclei` scanning) means dropping in a new module that declares its `requires`/`produces`; no existing module changes. See [06 Module System](06-module-system.md) for the loading mechanism and [21 Roadmap](21-roadmap.md) for the planned tool additions.
