# 21 — Future Roadmap

[← 20 Scalability](20-scalability.md) · [Index](../ARCHITECTURE.md) · Next: [22 Review Gate →](22-review-gate.md)

- **v1 (this design):** Web recon, sequential DAG, SQLite, graph-on-SQL, single AI provider, 6 tools (subfinder, httpx, katana, gau, ffuf, whatweb), AI summary + attack plan.
- **v1.x — tool breadth:** add naabu, nmap, nuclei, amass, rustscan, gowitness, masscan as new modules/parsers only ([06](06-module-system.md)). Automatic tool installation in [ToolManager](08-engine-services.md).
- **v2 — concurrency:** parallel scheduler (stage- and target-level), CommandExecutor concurrency/rate controls ([16](16-parallel-execution.md)).
- **v2.x — new domains:** API and Host recon modules + subtype tables + prompts; no core change.
- **v3 — intelligence depth:** richer semantic graph edges, AI chain-discovery across the full graph, multi-model routing and critic/verifier loops, embeddings-based asset similarity ([10](10-knowledge-graph.md), [11](11-ai-abstraction.md)).
- **v4 — distribution:** Postgres backend, queue/workers, containerized/remote execution, optional dedicated graph DB; multi-operator engagements ([17](17-distributed-execution.md)).
- **v5 — full domain coverage:** Network, AD, Cloud, Kubernetes, Containers, Mobile — each shipped as plugin packs.
