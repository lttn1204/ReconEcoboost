# 14 — Logging Strategy

[← 13 Configuration](13-configuration.md) · [Index](../ARCHITECTURE.md) · Next: [15 Output Management →](15-output-management.md)

- **Structured logging** (key/value, JSON-capable) so logs are queryable, not just readable.
- **Two surfaces:** human-friendly console output (progress, summaries) and a machine-readable run log file under the run workspace ([15](15-output-management.md)).
- **Correlation:** every log line carries `run_id` and `module`/`tool_run` ids — the through-line for debugging and the future distributed case ([17](17-distributed-execution.md)).
- **Levels with discipline:** the **raw tool output body is never logged at info**; only metadata (tool, redacted argv, duration, exit, byte counts) is. Raw captures are written to the run workspace as files and referenced by path. See [08 CommandExecutor](08-engine-services.md).
- **Redaction:** secrets/tokens and (configurably) sensitive target data are scrubbed before logging or before being sent to an external AI provider ([11](11-ai-abstraction.md)).
- **Audit trail:** because all execution flows through CommandExecutor and all AI calls through the provider base, the system produces a complete, replayable record of *what was run and what was asked of the model* — essential for offensive engagements and reporting.

## Design decision — structured + correlated + redacted

- **Advantages:** debuggable at scale, audit-ready, safe.
- **Disadvantages:** slightly more setup than print-style logging.
- **Alternatives:** plain logging (loses queryability/correlation), external observability stack (overkill for v1, but the structured format keeps that door open).
