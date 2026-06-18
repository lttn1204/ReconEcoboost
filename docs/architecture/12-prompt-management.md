# 12 — Prompt Management

[← 11 AI Abstraction](11-ai-abstraction.md) · [Index](../ARCHITECTURE.md) · Next: [13 Configuration →](13-configuration.md)

Prompts live **outside Python**, as versioned Markdown templates under a `prompts/` tree, loaded by a **Prompt Manager** that renders them with a template engine against a structured context.

- `summarize.md` — turn a normalized subgraph into a human-readable attack-surface summary.
- `classify.md` — label assets/endpoints by capability/risk category.
- `attack_plan.md` — produce ordered, evidence-linked, testable attack hypotheses.

> Per the project brief, prompt **contents are not generated** in this design phase.

## Design points

- **Why external:** prompts are tuned far more often than code; security researchers (not only Python devs) should edit them; they are reviewable in diffs; they can be A/B-versioned and pinned per run for reproducibility.
- **Structured inputs only:** the manager renders prompts from typed context objects (the curated subgraph from [10](10-knowledge-graph.md), entity lists, prior findings) — never from raw stdout. See [15 Output Management](15-output-management.md).
- **Versioning & metadata:** each prompt carries front-matter (version, intended model/capabilities, expected output schema). The run record stores which prompt versions were used.
- **Organized by domain & task:** `prompts/<domain>/<task>.md`, mirroring the module taxonomy, so adding a domain adds prompts without touching existing ones.

## Design decision — file-based prompt library

- **Advantages:** fast iteration, non-dev editability, diffable, reproducible.
- **Disadvantages:** templates and code can drift if the expected-schema contract isn't enforced (mitigated by validating responses against the declared schema in the [AI abstraction](11-ai-abstraction.md)).
- **Alternatives:** inline string prompts (fast but unmaintainable, untestable, dev-only); a prompt DB/SaaS (overkill, adds infra).
