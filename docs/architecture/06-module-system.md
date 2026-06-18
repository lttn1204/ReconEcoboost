# 06 — Module System & Loading Strategy

[← 05 Pipeline](05-pipeline.md) · [Index](../ARCHITECTURE.md) · Next: [07 Context Object →](07-context-object.md)

## 6.1 The Module contract

Every module is a class implementing a single abstract base (`Module`). It is **declarative about its place in the world** and **imperative only inside `run`**. The contract:

| Attribute | Meaning |
|---|---|
| `name` | Unique stable identifier (e.g. `asset_discovery`). |
| `domain` | `web` for v1; later `api`, `host`, `network`, `ad`, `cloud`, `k8s`, `container`, `mobile`. |
| `stage` | Logical category (discovery / probing / collection / analysis). |
| `requires` | Entity types this module needs as input (e.g. `[subdomain]`). |
| `produces` | Entity types this module emits (e.g. `[host]`). |
| `tool` | Logical tool name resolved through [ToolManager](08-engine-services.md) (e.g. `subfinder`), or `None` for pure-logic modules (normalization, AI). |
| `parser` | Reference to the Parser that turns this tool's output into records. |
| `optional` | Whether a failure is fatal to dependents or merely skipped. |
| `run(ctx)` | The only behavior. Receives [Context](07-context-object.md), returns a `ModuleResult`. |

`requires`/`produces` are typed against the **canonical entity taxonomy** (see [09 Database §9.2](09-database.md)), *not* against other module names. This is what makes stages replaceable: `dir_bruteforce` requires `url`, and does not care whether `katana` or `gau` produced those URLs.

## 6.2 Discovery & loading

Modules are discovered at runtime via a **registry** built from one of two mechanisms (both supported; entry points preferred for distribution):

- **Filesystem discovery:** packages under `modules/<domain>/` are imported; any subclass of `Module` self-registers via a decorator.
- **Entry-point discovery:** third parties ship modules as installable packages exposing a `reconecoboost.modules` entry point.

The registry yields a flat catalogue. The Orchestrator then filters by the selected pipeline (from `pipeline.yaml`, see [13 Configuration](13-configuration.md)) and domain.

## 6.3 Design decision — declarative DAG over hard-coded sequence

- **Rationale:** The pipeline is data (`requires`/`produces` + config), not code. New stages slot in by declaring their edges.
- **Advantages:** Zero-edit extensibility; automatic parallelizability detection ([16](16-parallel-execution.md)); cycle detection at load time; pipeline is introspectable and renderable.
- **Disadvantages:** Indirection — you can't read execution order top-to-bottom in one file; requires a solid taxonomy up front; mis-declared edges fail at plan time, not author time.
- **Future extensibility:** Conditional edges ("run ffuf only if katana found < N urls"), per-target sub-DAGs, AI-proposed dynamic stages.
- **Alternatives:** (a) Hard-coded ordered list — simplest, but every addition edits the orchestrator. (b) Airflow/Prefect-style external DAG engine — powerful but heavyweight for a laptop tool. (c) Plain event bus — flexible but order/visibility become emergent and hard to reason about.
