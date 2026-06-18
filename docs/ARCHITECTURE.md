# ReconEcoboost — Architecture Index

> **Status:** Design proposal — awaiting review.
> **Scope:** architecture and design only. No source code, migrations, or scripts.
> **Guiding invariant:** *The AI reasons. The Engine executes. Neither does the other's job.*

This document set is split into one file per component for easier tracking. Each file is self-contained and cross-links related components.

## How to read this

Start at **Design Principles** for the non-negotiables, then **High-Level Architecture** for the shape. The remaining files can be read in any order; each major decision carries a **Rationale / Advantages / Disadvantages / Future Extensibility / Alternatives** block.

## Index

| # | Component | File |
|---|---|---|
| 01 | Design Principles | [01-design-principles.md](architecture/01-design-principles.md) |
| 02 | High-Level Architecture | [02-high-level-architecture.md](architecture/02-high-level-architecture.md) |
| 03 | Component Diagram | [03-component-diagram.md](architecture/03-component-diagram.md) |
| 04 | Data Flow | [04-data-flow.md](architecture/04-data-flow.md) |
| 05 | Pipeline | [05-pipeline.md](architecture/05-pipeline.md) |
| 06 | Module System & Loading | [06-module-system.md](architecture/06-module-system.md) |
| 07 | Context Object | [07-context-object.md](architecture/07-context-object.md) |
| 08 | Engine Services (Executor / ToolManager / Parser / Normalizer) | [08-engine-services.md](architecture/08-engine-services.md) |
| 09 | Database Layer | [09-database.md](architecture/09-database.md) |
| 10 | Knowledge Graph Layer | [10-knowledge-graph.md](architecture/10-knowledge-graph.md) |
| 11 | AI Provider Abstraction | [11-ai-abstraction.md](architecture/11-ai-abstraction.md) |
| 12 | Prompt Management | [12-prompt-management.md](architecture/12-prompt-management.md) |
| 13 | Configuration System | [13-configuration.md](architecture/13-configuration.md) |
| 14 | Logging Strategy | [14-logging.md](architecture/14-logging.md) |
| 15 | Output Management | [15-output-management.md](architecture/15-output-management.md) |
| 16 | Future Parallel Execution | [16-parallel-execution.md](architecture/16-parallel-execution.md) |
| 17 | Future Distributed Execution | [17-distributed-execution.md](architecture/17-distributed-execution.md) |
| 18 | Folder Structure | [18-folder-structure.md](architecture/18-folder-structure.md) |
| 19 | Design-Decision Ledger | [19-decision-ledger.md](architecture/19-decision-ledger.md) |
| 20 | Scalability Considerations | [20-scalability.md](architecture/20-scalability.md) |
| 21 | Future Roadmap | [21-roadmap.md](architecture/21-roadmap.md) |
| 22 | Review Gate | [22-review-gate.md](architecture/22-review-gate.md) |

## Requirements → component map

The 15 requested components map onto the files above:

- Modular Pipeline → [05](architecture/05-pipeline.md), [06](architecture/06-module-system.md)
- Plugin-based Module System → [06](architecture/06-module-system.md)
- Context Object → [07](architecture/07-context-object.md)
- CommandExecutor → [08](architecture/08-engine-services.md)
- ToolManager → [08](architecture/08-engine-services.md)
- Configuration System → [13](architecture/13-configuration.md)
- Database Layer → [09](architecture/09-database.md)
- Knowledge Graph Layer → [10](architecture/10-knowledge-graph.md)
- AI Provider Abstraction → [11](architecture/11-ai-abstraction.md)
- Prompt Management → [12](architecture/12-prompt-management.md)
- Logging → [14](architecture/14-logging.md)
- CLI Entry Point → [02](architecture/02-high-level-architecture.md), [18](architecture/18-folder-structure.md)
- Output Management → [15](architecture/15-output-management.md)
- Future Parallel Execution → [16](architecture/16-parallel-execution.md)
- Future Distributed Execution → [17](architecture/17-distributed-execution.md)

**No implementation will begin until the [Review Gate](architecture/22-review-gate.md) questions are answered.**
