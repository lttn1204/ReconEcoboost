# 13 — Configuration System

[← 12 Prompt Management](12-prompt-management.md) · [Index](../ARCHITECTURE.md) · Next: [14 Logging →](14-logging.md)

Configuration is **layered YAML**, split by concern, merged into typed config objects at startup, with environment-variable and CLI overrides on top. Secrets (API keys) come from environment/secret store, **never** committed YAML.

```
defaults (shipped) ─▶ user config files ─▶ env vars ─▶ CLI flags   (later wins)
```

## The four files

| File | Purpose | Why it's separate |
|---|---|---|
| `tools.yaml` | Per-tool settings: binary name/path overrides, default flags, timeout, retry policy, version min, rate limits. | Tool config changes independently of pipeline shape; this is where operators tune aggressiveness/safety. Consumed by [ToolManager + CommandExecutor](08-engine-services.md). |
| `pipeline.yaml` | Which stages run, for which domain, enabled/disabled, stage-specific overrides, named profiles (quick / deep). | Defines *what runs*; lets users compose runs without code. Decoupled from how each tool is configured. Consumed by the Orchestrator ([05](05-pipeline.md), [06](06-module-system.md)). |
| `wordlists.yaml` | Named wordlist paths/sizes for ffuf and friends, mapped to logical names modules reference. | Wordlists are environment-specific assets that change with engagement; modules reference logical names, not paths. |
| `ai.yaml` | Active provider+model, parameters (temperature, max tokens), prompt-version pins, token/cost budgets, redaction policy. | AI config is a distinct concern with its own cadence and sensitivity; isolating it makes provider swaps and offline mode trivial ([11](11-ai-abstraction.md)). |

## Why split rather than one big file

Each file maps to a different role and change-cadence (tool ops vs. run composition vs. assets vs. AI), enabling least-surprise edits, cleaner diffs, and per-file overrides. Typed loading means a malformed config fails *at startup with a clear message*, not mid-run.

## Design decision — layered, concern-split, typed config

- **Advantages:** clear ownership, safe overrides, validated early, secrets kept out.
- **Disadvantages:** more files to learn; merge precedence must be documented (it is, above).
- **Alternatives:** single config file (simple, but mixes concerns and grows unwieldy); env-only (12-factor-pure but awful for nested recon config); code-as-config (powerful, but loses non-dev editability and diff safety).
