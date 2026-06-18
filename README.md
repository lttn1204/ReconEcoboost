# ReconEcoboost

**AI-assisted reconnaissance framework for web penetration testing and bug bounty.**

ReconEcoboost runs your recon tools, normalizes their output into a structured
knowledge graph, and uses an LLM to reason over that graph — producing an attack
surface summary and an evidence-linked attack plan. It is built so the **AI never
runs tools**: the engine executes, the AI reasons.

> ⚠️ For **authorized** security testing only (your own assets, an engagement with
> written permission, or an in-scope bug-bounty program).

---

## 1. What it is

- A **pipeline** of independently replaceable recon stages (plugins).
- A **deterministic engine** that runs external tools safely (timeouts, retries,
  no shell injection, full audit trail).
- A **SQLite store + knowledge graph** of everything discovered.
- An **AI layer** (Claude by default) that reads a curated slice of the graph and
  emits structured findings — never raw tool output.
- A **report generator** (JSON / Markdown / HTML).

Core invariant: **AI reasons, the Engine executes.** A hallucinating or
compromised model can never directly spawn a process or see raw stdout.

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 2. How it works

```
target (scope)
   │
   ▼
Recon module ──uses──▶ ToolManager (find binary, version)
   │                        │
   │                        ▼
   │                  CommandExecutor (run argv, timeout, retry, capture)
   │◀── raw stdout ─────────┘
   ▼
Parser (tool text → typed records)
   ▼
Normalizer (dedupe, merge sources, canonical keys)
   ▼
SQLite store  ◀────▶  Knowledge graph (assets + typed relations)
   ▼
Analysis module → curated subgraph (JSON) → Prompt → AI provider
   ▼
Structured findings (summary, attack plan) → store
   ▼
Output writer → report.json / report.md / report.html
```

The boundary where text becomes structure (the **Parser**) is guarded: raw
stdout dies there and never reaches the database, the graph, or the LLM.

---

## 3. The pipeline (v1, web domain)

Stages form a dependency DAG resolved at runtime — order comes from each
module's `requires`/`produces`, not a hard-coded list.

| Stage | Tool | Consumes → Produces | What it does |
|---|---|---|---|
| `asset_discovery` | subfinder | scope → subdomain | Enumerate subdomains (passive) |
| `vhost_discovery` | ffuf | scope → subdomain | Fuzz the `Host:` header to find virtual hosts (wordlist: `vhosts`) |
| `alive_detection` | httpx | subdomain → host | Probe which hosts answer HTTP |
| `crawling` | katana | host → url, endpoint | Active crawl of live hosts |
| `historical_urls` | gau | host → url | Pull historical URLs |
| `tech_fingerprint` | whatweb | host → technology | Detect technologies |
| `dir_bruteforce` | ffuf | host → url | Content/dir brute-force, per configured HTTP method (GET/POST/…) |
| `url_probe` | httpx | url → url | Probe discovered URLs; record each one's status/size (for reports/AI) |
| `nuclei_scan` | nuclei | host → findings | Template scan of **every live subdomain's host root** → **verified** `finding` rows |
| `screenshot` | _(future: gowitness)_ | host → artifact | Optional, not wired in v1 |
| `normalization` | — | url… → host links | Cross-tool consolidation |
| `ai_recon_intel` | Claude | graph → intel | Compile tech + interesting endpoints + sensitive cases for manual analysis (AI mode ≥ `analyze`) |
| `ai_pentest` | Claude | intel → vulnerabilities | AI-driven, testable vulnerability hypotheses with steps (AI mode `pentest`) |

The two AI stages only run depending on the **AI mode** (see [§AI modes](#ai-modes-what-the-ai-does)).

Identity model: a `host` is keyed by its origin (`scheme://netloc`), so relations
wire up deterministically: `subdomain ─resolves_to→ host`, `url ─belongs_to→ host`,
`host ─uses→ technology`.

**Scope is enforced** at the module boundary: out-of-scope inputs are never
scanned and out-of-scope results are dropped before they are stored.

---

## 4. Install

Requires **Python 3.10+**.

```bash
# from the project root
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `reconecoboost` CLI.

### Clone & run on another machine

```bash
git clone <your-repo-url> && cd ReconEcoboost
python3 -m venv .venv && source .venv/bin/activate
pip install -e .                       # installs the CLI + anthropic SDK
cp config/scope.example.yaml config/scope.yaml   # then edit your scope
# install the recon tools (below), set ANTHROPIC_API_KEY if using AI
reconecoboost --run
```

For the AI step on your **subscription**, log in once (machine-level, not
per-directory): run `claude` then `/login`. Leave `ANTHROPIC_API_KEY` unset.

What is **not** in the repo (gitignored, recreated per machine):
`config/scope.yaml` (engagement targets — copy from `scope.example.yaml`),
any `config/*.local.yaml` (machine-specific overrides), `runs/` + `results/`
(scan output), `.venv/`, and large wordlists (only small starters ship). No API
keys or hostnames are committed.

**Machine-specific config → `*.local.yaml`.** Any `config/<section>.local.yaml`
is gitignored and deep-merged over `config/<section>.yaml` at load time. Use it
for paths/values that shouldn't be shared — e.g. pin the real httpx binary in
`config/tools.local.yaml`:

```yaml
tools:
  httpx:
    path: /your/go/bin/httpx
```

### External recon tools

Install the v1 tools and put them on your `PATH` (or set explicit paths in
[config/tools.yaml](config/tools.yaml)):

- [subfinder](https://github.com/projectdiscovery/subfinder),
  [httpx](https://github.com/projectdiscovery/httpx),
  [katana](https://github.com/projectdiscovery/katana),
  [gau](https://github.com/lc/gau),
  [ffuf](https://github.com/ffuf/ffuf),
  [whatweb](https://github.com/urbanadventurer/WhatWeb),
  [nuclei](https://github.com/projectdiscovery/nuclei)

Check what's available for your selected pipeline:

```bash
reconecoboost example.com --preflight
```

Missing tools are reported and their stages are skipped gracefully — the rest of
the pipeline still runs.

### AI provider

The default provider is **Claude**. Set your key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

To run **without** any AI calls (offline, or for confidential engagements), use
the stub provider (see §6).

---

## 5. Configure

Configuration is split by concern under [config/](config/) (layered:
shipped defaults → files → env vars → CLI flags). See
[docs/architecture/13-configuration.md](docs/architecture/13-configuration.md).

| File | Purpose |
|---|---|
| [tools.yaml](config/tools.yaml) | Binary names/paths, timeouts, retries per tool |
| [pipeline.yaml](config/pipeline.yaml) | Which stages run; named profiles (`default`, `quick`) |
| [wordlists.yaml](config/wordlists.yaml) | Logical name → wordlist path (see Wordlists below) |
| [ai.yaml](config/ai.yaml) | Provider, model, max tokens, effort, prompt dir |
| [scope.yaml](config/scope.yaml) | In-scope / out-of-scope host patterns (see Scope below) |

Any value can be overridden by an environment variable using `__` to nest:

```bash
RECONECOBOOST__AI__PROVIDER=stub
RECONECOBOOST__AI__MODEL=claude-opus-4-8
RECONECOBOOST__TOOLS__DEFAULTS__RATE_LIMIT=20    # 20 requests/sec for all active tools
```

### Scope (which hosts get scanned)

Reconnaissance discovers many subdomains, but they aren't all in scope. Define
scope in [config/scope.yaml](config/scope.yaml) — it controls which hosts the
**active** stages (alive probing, crawling, **directory fuzzing**, fingerprinting)
are allowed to touch. Discovery (subfinder) always runs against the seed target
you pass on the CLI; everything downstream is gated by these patterns.

```yaml
in_scope:
  - "*.example.com"     # all subdomains of example.com
  - "example.com"       # ...and the apex (omit to exclude the apex)
out_of_scope:
  - "admin.example.com" # never touched, even though it matches *.example.com
```

Pattern syntax:

| Pattern | Matches |
|---|---|
| `example.com` | the exact host (apex) only — **not** its subdomains |
| `*.example.com` | any subdomain (`a.example.com`, `x.y.example.com`) — **not** the apex |

`out_of_scope` wins over everything. **The seed target(s) are always in scope**
(you explicitly asked to scan them) — so `in_scope: ["*.example.com"]` with
target `example.com` still scans `example.com` itself, not only its subdomains.
If `in_scope` is empty, the seed target and everything discovered under it are
in scope (minus `out_of_scope`). This is how
you stop ffuf/katana from running against subdomains you're not allowed to test —
e.g. set `in_scope: ["example.com"]` to fuzz only the apex, or list the specific
subdomains you're authorized to hit.

**Targets vs scope.** The target(s) you pass on the CLI are the *seed* (what
subfinder enumerates / what gets probed); `in_scope` is the *filter*. If you run
with **no CLI target**, the seed is taken from `in_scope` (a `*.example.com`
entry seeds `example.com`), so you can just configure `scope.yaml` and run
`reconecoboost --run`. Passing targets on the CLI overrides this.

**Subdomain enumeration is automatic (`--enumerate auto`, the default).**
Whether subfinder runs is decided from the scope's use of a `*` wildcard:

| `in_scope` | Enumeration |
|---|---|
| has a wildcard, e.g. `*.example.com` | **on** — discover subdomains |
| exact hosts only, e.g. `example.com` or `a.com`, `b.com` | **off** — scan exactly those (no subfinder) |
| empty (unconstrained) | on — discover under the seed |

So a single-domain or fixed-host engagement skips enumeration with no extra
flags. Force it with `--enumerate always`, or disable with `--enumerate never`.

**Recursive discovery (depth).** When enumeration is on, the discovery tools
(`subfinder` and `vhost_discovery`) can recurse: each newly-found subdomain is
re-fed as a seed. Set the depth in `pipeline.yaml` or with `--depth`:

```yaml
discovery:
  recursive_depth: 1   # 1 = single pass (default); 2 = subdomains-of-subdomains;
                       # 100 = keep going until no new subdomains are found
```

```bash
reconecoboost example.com --run --enumerate always --depth 2
```

Each level only recurses into **in-scope** subdomains, and it stops early when a
level finds nothing new (so a high depth like `100` just means "until
exhausted"). Note depth multiplies tool runs — combine with scope and rate
limits on large targets.

### HTTP methods for fuzzing

By default `dir_bruteforce` fuzzes with `GET`. To test more verbs, set the list
in [config/tools.yaml](config/tools.yaml) under `ffuf`:

```yaml
ffuf:
  methods: ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "DEBUG"]
```

It runs one ffuf pass per method (per host) and stores per-method status/size on
each URL, so the agent (and reports) can spot anomalies — e.g. a path that's
`GET 403` but `POST 200`, or `TRACE`/`DEBUG` enabled:

```json
"methods": { "GET": {"status":403,"length":20}, "POST": {"status":200,"length":512} }
```

The raw output is saved as **one file per host** —
`results/<run>/dir_bruteforce-<host>.txt` — with all methods together (grouped by
URL), not split per method. Each method multiplies the work
(methods × hosts × wordlist), so add them deliberately and pair with the rate limit.

### Vulnerability scanning (nuclei)

`nuclei_scan` runs nuclei against the **host root of every live subdomain**,
writing verified `finding(kind="vulnerability")` rows that the AI then triages.
It does **not** scan individual URLs — nuclei's templates are root-relative, so
host roots cover the bulk of detections. Configure in
[config/tools.yaml](config/tools.yaml) under `nuclei`:

```yaml
nuclei:
  severity: ["low", "medium", "high", "critical"]  # [] = all (incl. info)
  # max_targets: 500   # cap hosts fed to nuclei
  # timeout_s: 1800    # raise for large scopes
```

Notes: the default `severity` drops `info` (so a clean run can legitimately be
empty — set `severity: []` to see info-level output). It scans on its own
recon-stage run; `--run-id` only re-runs the AI stages, not nuclei.

### Rate limiting (requests/sec)

Throttle how fast the active tools hit a target — set it in
[config/tools.yaml](config/tools.yaml). `defaults.rate_limit` applies to every
tool that defines a `rate_flag`; a per-tool `rate_limit` overrides the default.
The value is injected as the tool's **native** requests-per-second flag, so it
limits real HTTP requests, not just process launches.

```yaml
defaults:
  rate_limit: 20          # requests/sec for all active tools (null = unlimited)
tools:
  httpx:
    rate_flag: "-rl"      # the tool's own rate flag
    rate_limit: null      # null = inherit default; a number overrides; 0 = unlimited
  ffuf:
    rate_flag: "-rate"
    rate_limit: 10        # ffuf brute-force kept slower than the rest
```

Resolution: per-tool `rate_limit` if set, otherwise `defaults.rate_limit`;
`null`/`0` or a tool without a `rate_flag` means unlimited. Passive tools
(subfinder, gau) and single-target tools (whatweb) have no `rate_flag` and are
not throttled. Tool flag names vary by version — adjust `rate_flag` to match
your installed binary (`subfinder`/`httpx`/`katana` use `-rl`, `ffuf` uses
`-rate`).

Prompts live outside code under [prompts/web/](prompts/web/) and can be edited
without touching Python.

### Wordlists

Custom wordlists live in a managed [wordlists/](wordlists/) folder, organized per
tool:

```
wordlists/
  ffuf/
    directories.txt   # used by dir_bruteforce (logical name: directories)
    common.txt        # logical name: common
    vhosts.txt        # used by vhost_discovery (logical name: vhosts)
```

[config/wordlists.yaml](config/wordlists.yaml) maps a **logical name** to a path,
and the module uses whatever file sits there — so to use your own list you either
replace the file's contents or point the config entry at a new file. Shipped
files are minimal working starters; replace them with your real lists (e.g.
SecLists). Lines starting with `#` are ignored (ffuf runs with `-ic`). Only
tools that take a wordlist get a folder (v1: ffuf); see
[wordlists/README.md](wordlists/README.md) for adding more.

---

## 6. Usage

### Plan only (default — shows the resolved DAG, runs nothing)

```bash
reconecoboost example.com
```

### Preflight (check tool availability + versions)

```bash
reconecoboost example.com --preflight
```

### Run the full pipeline

```bash
reconecoboost example.com --run
```

### Run a lighter profile

```bash
reconecoboost example.com --run --profile quick
```

### Test ONLY specific hosts (no subdomain enumeration)

Pass the exact hosts as targets and use the `direct` profile — subfinder is
skipped and only the hosts you list are probed/crawled/fuzzed:

```bash
reconecoboost a.com.vn elearning.a.com.vn --run --profile direct
```

(To also enumerate subdomains but still restrict scanning to a set, use the
default profile and set `in_scope` in `scope.yaml`.)

<a id="ai-modes-what-the-ai-does"></a>
### AI modes — what the AI does

Choose how much the AI does after recon, via `ai.mode` in
[ai.yaml](config/ai.yaml) or `--ai-mode` on the CLI:

| Mode | Stages run | What you get |
|---|---|---|
| `off` | recon only | tools only — no LLM invoked |
| `analyze` | + `ai_recon_intel` | compiled recon intelligence (technologies, interesting endpoints, sensitive cases from bug-hunter experience) for **your manual analysis/pentest** |
| `pentest` | + `ai_recon_intel` + `ai_pentest` | the above, then AI **vulnerability hunting** — concrete, testable hypotheses with steps |

```bash
reconecoboost example.com --run --ai-mode off       # tools only
reconecoboost example.com --run --ai-mode analyze   # tools + recon intel
reconecoboost example.com --run --ai-mode pentest   # tools + intel + AI pentest
reconecoboost example.com --run --no-ai             # alias for --ai-mode off
```

**Analyze an already-scanned run (no recon re-run).** Point `--run-id` at an
existing run to run *only* the AI stages against its stored data:

```bash
reconecoboost --run-id <RUN_ID> --ai-mode analyze   # AI analysis only
reconecoboost --run-id <RUN_ID> --ai-mode pentest   # AI analysis + pentest
```

It reuses `runs/<RUN_ID>/recon.db`, writes the findings back into it, and
regenerates the reports. Re-running replaces the prior AI findings (no
duplicates). The run id is printed at the end of every scan (and is the
`runs/<id>/` folder name).

The AI tasks reason over a curated graph and write structured `finding` rows
(`recon_intel`, `vulnerability`) into the DB and reports — they never execute
exploits themselves.

### Provider: which AI runs

Set `provider` in [ai.yaml](config/ai.yaml):

- **`claude`** — metered Messages API (needs `ANTHROPIC_API_KEY`). `model` is a
  full id like `claude-sonnet-4-6`.
- **`claude-code`** — runs the `claude` CLI headless, using your **Pro/Max
  subscription** instead of per-token API billing. Requirements:
  - Claude Code installed and logged in (`claude` → `/login`).
  - `ANTHROPIC_API_KEY` **unset** (the adapter unsets it for the CLI; if it's set
    globally, Claude Code would bill the API instead of the subscription).
  - `model` is a CLI alias (`sonnet`, `opus`) or full id.
  - Note: automated use of a consumer subscription is subject to Anthropic's
    usage policy and your plan's rate limits.
- **`stub`** — offline placeholder that returns nothing (AI stages still run but
  produce no findings). To skip AI entirely use `--ai-mode off` / `--no-ai`.

### All flags

| Flag | Meaning |
|---|---|
| `target ...` | One or more seed targets, e.g. `a.com.vn elearning.a.com.vn` (positional) |
| `--run` | Execute the pipeline (default is plan-only) |
| `--preflight` | Check the tools the pipeline needs |
| `--enumerate` | `auto` (default) / `always` / `never` — subdomain enumeration (auto = only if scope has a `*`) |
| `--depth` | Recursive discovery depth (overrides `pipeline.discovery.recursive_depth`) |
| `--ai-mode` | `off` / `analyze` / `pentest` — how much the AI does (overrides `ai.mode`) |
| `--run-id` | Run only the AI stages on an existing run's data (no recon); use with `--ai-mode` |
| `--no-ai` | Alias for `--ai-mode off` (recon only; no LLM invoked) |
| `--domain web` | Recon domain (only `web` in v1) |
| `--profile default` | Pipeline profile from `pipeline.yaml` (`default`, `quick`, `direct`) |
| `--config-dir config` | Directory holding the YAML config |
| `--log-level INFO` | Logging level |
| `--json-logs` | Emit structured JSON logs |

Run without installing the package (dev):

```bash
PYTHONPATH=src python -m reconecoboost.cli.main example.com --run
```

---

## 7. Output

Each run creates a self-contained workspace at `runs/<run_id>/`:

| File | Contents |
|---|---|
| `recon.db` | SQLite database — the full normalized dataset + graph |
| `report.json` | Machine-readable report (everything) |
| `report.md` | Human report: overview, findings, assets, tool runs |
| `report.html` | Same, browser-friendly |

Reports are built **from the database**, so you can re-generate them later
without re-running any tools.

### Raw tool output — `results/<run_id>/`

The output of each tool invocation is also saved to disk for traceability,
under `results/<run_id>/<stage>-<n>.<ext>` (e.g. `alive_detection-00.jsonl`).
Most are saved verbatim; `dir_bruteforce-<n>.txt` is rendered as a **readable
table** — one endpoint per line with status, size, words, and URL (sorted by
status then size), instead of ffuf's raw JSON blob. Each file is linked back
into the database:

- `tool_run.capture_path` → the raw file for that invocation
- `provenance.raw_ref` → the raw file an asset came from

So you can trace any asset in `recon.db` to the exact tool output that produced
it. (Empty outputs aren't filed; the `tool_run` row still records the run.)
`results/` is gitignored except `.gitkeep`.

---

## 8. Extending

Adding a tool is **a new module + a new parser** — no existing code changes:

1. Write a parser in [src/reconecoboost/modules/web/parsers.py](src/reconecoboost/modules/web/parsers.py)
   (`@register_parser`, pure text → `ParsedRecord`).
2. Write a module subclassing `ToolModule` in
   [src/reconecoboost/modules/web/](src/reconecoboost/modules/web/) declaring its
   `tool`, `parser`, `requires`, `produces`.
3. Add the stage name to a profile in [config/pipeline.yaml](config/pipeline.yaml).

The orchestrator slots it into the DAG automatically. New AI providers are added
the same way under [src/reconecoboost/ai/](src/reconecoboost/ai/) and selected via
`ai.yaml`.

---

## 9. Project layout

```
config/      shipped configuration (tools/pipeline/wordlists/ai)
prompts/     external prompt templates (editable, versioned)
docs/        architecture documents (ARCHITECTURE.md + architecture/)
src/reconecoboost/
  cli/         entry point + run lifecycle
  core/        Context, BaseModule, models, taxonomy, errors
  config/      config loader
  orchestration/  module registry + pipeline DAG
  engine/      CommandExecutor, ToolManager, parsers, normalizer
  modules/     recon plugins (web/) + ToolModule base
  analysis/    AI-facing modules (summary, attack planning)
  ai/          provider abstraction + Claude/stub adapters
  prompts/     prompt manager
  persistence/ SQLite store + repositories
  graph/       knowledge graph (graph-on-SQL)
  output/      report builders + writers
  logging/     structured logging
tests/       unit tests
runs/        per-run workspaces (gitignored)
```

---

## 10. Status & roadmap

**v1 is complete**: the full web pipeline runs end-to-end (recon → store → graph
→ AI → reports) with the 6 v1 tools, behind config-driven, swappable layers.

The architecture is designed to grow without rework:

- **v1.x** — more tools (naabu, nmap, nuclei, gowitness, …) as drop-in modules.
- **v2** — parallel execution (the DAG already encodes it).
- **later** — new domains (API, host, network, AD, cloud, k8s, containers, mobile),
  distributed execution, a graph database backend.

See [docs/architecture/21-roadmap.md](docs/architecture/21-roadmap.md).

---

## Development

```bash
.venv/bin/python -m pytest -q     # run the test suite
```
