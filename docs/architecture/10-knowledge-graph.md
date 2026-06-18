# 10 — Knowledge Graph Layer

[← 09 Database](09-database.md) · [Index](../ARCHITECTURE.md) · Next: [11 AI Abstraction →](11-ai-abstraction.md)

## 10.1 What it is

A typed, directed property graph layered **on top of** the relational store ([09](09-database.md)): nodes are `asset` rows, edges are `relation` rows. In v1 it is *materialized in SQLite* (no extra dependency) and queried via recursive CTEs and the repository layer; the interface is written so it can be backed by a real graph DB (Neo4j / Memgraph) later without touching callers.

## 10.2 Why a graph at all

Recon facts are *relationships*, and vulnerabilities live in the relationships, not the isolated facts. A list of URLs and a list of hosts are inert; the *paths between them* are where attack surface emerges. The example chain:

```
Login ──issues──▶ OTP ──establishes──▶ Session ──encodes──▶ JWT
   │                                                          │
   └──triggers──▶ Password Reset ◀──governs── Authorization ──┘
                          │
                          └──affects──▶ Device Registration
```

Each box is an `asset` (an endpoint/capability node); each arrow is a typed `relation`. The graph lets the system ask *structural* questions: "is there a path from an unauthenticated endpoint to a state-changing one?", "does password-reset reach session issuance without re-auth?", "which JWT-bearing endpoints share a signing surface?"

## 10.3 How edges are created

- **Deterministically by the Normalizer / Graph Builder:** structural facts (subdomain→host, host→url, url→technology, url→parameter) become edges as data lands. These are high-confidence, rule-derived edges. See [08 §8.4](08-engine-services.md).
- **Semantically by analysis modules:** behavioral/logical edges (login→issues→OTP, reset→governs→authorization) are inferred — partly by heuristics over endpoint names/flows, partly proposed by the AI and stored as edges with `confidence` and `source = ai`. AI-proposed edges are *flagged* and never silently trusted as ground truth.

## 10.4 How the AI reasons over it

The AI is **not** handed the whole graph. An analysis module extracts a **relevant subgraph** (a scoped neighborhood — e.g., all auth-related nodes and their 2-hop neighbors), serializes it as a compact, typed, structured description (nodes with types/attributes, edges with types), and renders it through a prompt template ([12](12-prompt-management.md)). The AI then:
- **Summarizes** the subgraph into human-readable attack surface.
- **Classifies** nodes (auth surface, data-mutation, file-upload, SSRF-prone, …).
- **Finds chains:** identifies multi-step paths of interest (e.g., reset→session→JWT without re-auth → account-takeover hypothesis).
- **Plans:** emits ordered, testable hypotheses, each linked back to the specific nodes/edges it concerns.

Crucially the AI's output is *structured and grounded*: every hypothesis references concrete `asset`/`relation` IDs, so a human (or a future automated verifier) can trace each claim to evidence. AI outputs are written back as `finding` and (optionally) new `relation` rows — closing the loop so later reasoning builds on earlier reasoning.

## 10.5 Design decision — graph-on-SQL now, graph-DB-ready interface

- **Advantages:** no new infra in v1; relational integrity and graph traversal from one store; clean upgrade path.
- **Disadvantages:** deep/variable-length traversals are clumsier and slower in SQL than in Cypher.
- **Alternatives:** Neo4j/Memgraph from day one (best traversal, but ops + dependency weight unjustified for v1); in-memory graph (NetworkX) per run (great for analysis, but not durable — usable as a transient accelerator over the durable store).
