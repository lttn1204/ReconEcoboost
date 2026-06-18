# 08 — Engine Services

[← 07 Context Object](07-context-object.md) · [Index](../ARCHITECTURE.md) · Next: [09 Database →](09-database.md)

The deterministic "muscle" of the framework: CommandExecutor, ToolManager, Parser registry, Normalizer. These are the security- and reliability-critical chokepoints.

## 8.1 CommandExecutor

A single chokepoint through which **all** external processes run.

Responsibilities:
- **Process execution** from an **argument vector** (`["subfinder", "-d", target]`), never a shell string — eliminates shell-injection and quoting bugs.
- **Timeouts** (per-invocation, configurable) with guaranteed process-tree termination.
- **Retries** with backoff for transient failures, governed by a typed policy (max attempts, which exit codes/patterns are retryable).
- **Capture** of stdout, stderr, exit code separately, with optional streaming to disk for large outputs.
- **Timing** (wall-clock duration) recorded for every invocation.
- **Structured logging** of each invocation (tool, redacted args, duration, exit, bytes captured) — never the raw output body at info level. See [14 Logging](14-logging.md).
- **Typed error handling:** returns a result object (success | timeout | non-zero | spawn-failure), not raw exceptions leaking to modules.
- **Resource guards (future seam):** concurrency limits, rate limiting, niceness/cgroup hooks. See [16 Parallel](16-parallel-execution.md).

### Why modules must never call `subprocess.run()` directly

- **Consistency:** one place defines timeout/retry/logging semantics; behavior is uniform across all tools.
- **Security:** argv-only execution and centralized scope/arg validation prevent injection and accidental out-of-scope targeting.
- **Observability:** every external action is logged and timed identically — essential for an audit trail in offensive work.
- **Testability:** modules are tested by injecting a fake Executor; no real processes spawn in unit tests.
- **Evolvability:** swapping local exec for containerized exec, remote exec, or a rate-limited pool happens in one class — modules are untouched ([17 Distributed](17-distributed-execution.md)).

*Disadvantages:* a thin abstraction overhead and one more interface to learn. *Alternative:* let modules call subprocess — rejected: it scatters policy, defeats testing, and is a security liability in a pentest tool.

## 8.2 ToolManager

Owns the relationship between *logical tool names* and *real binaries*.

Responsibilities:
- **Binary discovery:** resolve `subfinder` → absolute path (PATH lookup + config override paths).
- **Version detection:** invoke the tool's version probe (via CommandExecutor), parse and cache the version.
- **Dependency / capability validation:** verify required tools for the selected pipeline exist *before* the run starts, failing fast with a clear list of what's missing.
- **Health/preflight:** confirm a binary is executable and the version meets a declared minimum.
- **Future automatic installation:** a pluggable installer per tool (go install / package manager / download-and-verify-checksum) behind a stable interface — *designed now, not built in v1*.

Integration with modules: a module declares `tool = "subfinder"`; at `run`, it asks `ctx.tools.resolve("subfinder")` and receives a validated, versioned handle, then hands the argv to the Executor. Modules never hardcode paths and never check existence themselves.

### Design decision — central tool registry

- **Advantages:** one preflight covers the whole run; version data is captured into the run record (reproducibility); install strategy is centralized.
- **Disadvantages:** indirection; version-parsing is per-tool brittle (mitigated by treating version as best-effort metadata, not a gate unless configured).
- **Alternatives:** per-module discovery (duplicative, inconsistent), or assume tools exist (poor UX, late failures).

## 8.3 Parser registry

One parser per tool output format. A parser converts **raw text → list of typed `ParsedRecord`** and nothing else (no I/O, no DB). Parsers are pure functions of their input → trivially testable against fixture files. The registry maps tool/format → parser so a module simply declares which parser consumes its tool's output.

Most chosen v1 tools support structured output (httpx, katana, gau, ffuf emit JSON / JSONL; subfinder emits line-oriented; whatweb emits JSON). **Prefer structured tool output over scraping human text** wherever a tool offers it — it shrinks the parser's fragility surface dramatically.

## 8.4 Normalizer

Turns tool-shaped `ParsedRecord`s into the **canonical entity model** ([09 §9.2](09-database.md)): deduplicates, merges multi-source facts (a URL seen by both katana and gau becomes one entity with two provenance sources), resolves natural keys, and emits `(entities, relations)` for persistence. This is where "many tools, one truth" is enforced.

**Why this layering (Parser separate from Normalizer):** parsing is *tool-coupled*; normalization is *domain-coupled*. Keeping them apart means a new tool needs only a new parser (the normalizer is reused), and a taxonomy change touches only the normalizer (parsers are untouched).
