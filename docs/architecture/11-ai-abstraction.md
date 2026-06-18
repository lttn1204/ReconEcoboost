# 11 — AI Provider Abstraction

[← 10 Knowledge Graph](10-knowledge-graph.md) · [Index](../ARCHITECTURE.md) · Next: [12 Prompt Management →](12-prompt-management.md)

## 11.1 The interface

A single `AIProvider` interface defines provider-agnostic operations: a `complete`/`generate` call that takes a rendered prompt + parameters and returns a **structured, validated response**, plus capability metadata (context window, supports-structured-output, supports-streaming, token accounting). Concrete adapters implement it:

```
            ┌────────────────────────────────┐
            │        AIProvider (ABC)         │
            │  generate(prompt, schema, opts) │
            │  capabilities()                 │
            └───────────────┬────────────────┘
       ┌─────────┬──────────┼──────────┬───────────┐
       ▼         ▼          ▼          ▼           ▼
  ┌────────┐┌────────┐ ┌────────┐ ┌────────┐  ┌────────┐
  │ Claude ││ OpenAI │ │ Gemini │ │ Ollama │  │ Local  │
  └────────┘└────────┘ └────────┘ └────────┘  └────────┘
```

## 11.2 How switching stays cheap

- **Selection is config, not code:** `ai.yaml` ([13](13-configuration.md)) names the active provider and model; the factory instantiates the right adapter. Switching from Claude to a local Ollama model is a config edit.
- **Prompts are external ([12](12-prompt-management.md))** and provider-neutral, so they don't bake in provider quirks.
- **Structured I/O is the contract:** modules ask for a response *matching a schema*; each adapter is responsible for getting structured output from its provider (native structured-output, tool/function calling, or strict-JSON-then-validate). Callers receive a validated object regardless of provider.
- **Cross-cutting concerns live in a base/decorator layer, not the adapters:** retries, rate limiting, token budgeting, response caching, and redaction wrap every provider uniformly.

**Default provider:** Claude (e.g. an Opus/Sonnet-class model) given this environment, with Ollama/local as the offline-capable fallback — important for engagements where sending recon data to a third-party API is contractually forbidden.

## 11.3 Design decision — thin provider adapters + structured contract

- **Advantages:** provider independence; offline/local capability for sensitive engagements; uniform reliability/cost controls; testable with a fake provider.
- **Disadvantages:** lowest-common-denominator risk (must design for capability differences); structured-output emulation varies in quality across providers.
- **Future extensibility:** multi-provider routing (cheap model for classification, strong model for planning), ensemble/critic patterns, embeddings provider for graph similarity.
- **Alternatives:** hardcode one SDK (cheapest to start, painful to migrate, blocks offline use); adopt a heavy framework (LangChain et al. — more abstraction surface and churn than a focused tool wants).
