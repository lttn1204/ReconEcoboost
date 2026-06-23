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
| `dns_resolve` | dnsx | subdomain → subdomain | Resolve + **DNS brute** (`word.<apex>`), attach IP(s), flag `internal`, filter wildcard (brute only on wildcard scope) |
| `permutation` | alterx → dnsx | subdomain → subdomain | **Permute** known names (`api`→`api-dev`,`api2`,…) then resolve; keep resolving names (enumeration/wildcard only) |
| `alive_detection` | httpx | subdomain → host | Probe which hosts answer HTTP (skips `internal` by default) |
| `vhost_discovery` | ffuf | subdomain → host | Fuzz `Host:` over the **dnsx IP inventory** → DNS-less vhosts registered as live hosts (enumeration/wildcard only) |
| `crawling` | katana | host → url, endpoint | Active crawl of live hosts |
| `historical_urls` | gau | host → url | Pull historical URLs |
| `tech_fingerprint` | whatweb | host → technology | Detect technologies |
| `dir_bruteforce` | ffuf | host → url | Content/dir brute-force, per configured HTTP method (GET/POST/…) |
| `url_probe` | httpx | url → url | Probe discovered URLs; record each one's status/size (for reports/AI) |
| `js_fetch` | httpx | url → response bodies | Fetch discovered JS/JSON (and live URLs) **once**; cache bodies for the two consumers below |
| `secret_scan` | regex | bodies → findings | Regex-scan cached bodies for exposed secrets (leaklens-style) → **redacted** `finding(kind="secret")`; toggleable |
| `js_intel` | regex | bodies → url/findings | Mine endpoints / cloud-URLs / source-maps from cached JS (leaklens `--js-intel`); toggleable |
| `content_subdomains` | regex | bodies → subdomain | Extract in-scope subdomains referenced in HTML/JS/CSP (catches hosts brute/passive miss); toggleable, independent |
| `nuclei_scan` | nuclei | host → findings | Template scan of **every live subdomain's host root** → **verified** `finding` rows |
| `screenshot` | _(future: gowitness)_ | host → artifact | Optional, not wired in v1 |
| `normalization` | — | url… → host links | Cross-tool consolidation |
| `triage` | — (deterministic) | assets + findings → ranked shortlist | Score/rank assets by signal, group noise → `results/<run_id>/triage.{json,txt}` + report "Top Targets" (**no LLM, zero tokens**) |
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

### Secret scanning (leaklens-style, deterministic)

The shared **`js_fetch`** stage fetches the bodies of every URL recon discovered
(Katana **crawl**, gau **history**, ffuf **dir-fuzzing**, url_probe) **once** with
httpx and caches them under `results/<run_id>/responses/`. It selects a URL if its
**extension** is interesting (`.js/.json/.env/…`) **or** it's **live**
(`scan_status`, default `[200]`) — so live HTML/API endpoints from fuzzing and URL
history are included too; binary/media (images, fonts, css) are always skipped.
`secret_scan` and `js_intel` then both read those cached bodies (no second
network pass).

`secret_scan` runs a deterministic regex rule engine (gitleaks/leaklens lineage)
over the bodies — AWS/GCP/GitHub/Slack/Stripe keys, private keys, JWTs, generic
`api_key=…` assignments, etc. **No LLM, zero tokens.**

For pentest, findings store the **full secret value** (rule + value + URL/line) so
you can verify it immediately. Set `secret_scan.redact: true` to mask it instead
(`ghp_…AA (40 chars)`). Each becomes a `finding(kind="secret")`, and triage
promotes secret-bearing URLs into the curated AI context as guaranteed leads.
Output:

- `results/<run_id>/secrets.txt` / `secrets.json`
- a `finding(kind="secret")` per match (shown in the report)

Configure in [config/pipeline.yaml](config/pipeline.yaml). What to fetch lives in
`js_fetch` (shared); what to do with the bodies lives in `secret_scan`/`js_intel`:

```yaml
js_fetch:                        # the single shared fetch
  enabled: true                  # off => disables both secret_scan and js_intel
  extensions: [js, json, map, txt, xml, yml, yaml, env, config, bak]
  scan_status: [200]             # also fetch live URLs of any extension
  max_urls: 500

secret_scan:
  entropy:                       # Shannon-entropy detection — catches unknown/custom
    enabled: false               #   secrets no regex matches (higher recall, more FP)
    base64_threshold: 4.5
    hex_threshold: 3.0
    min_length: 20
```

Rules live in [analysis/secrets.py](src/reconecoboost/analysis/secrets.py):
- **~34 precise provider regexes** ([gitleaks](https://github.com/gitleaks/gitleaks)
  lineage): AWS, Google, GitHub, OpenAI, Anthropic, GitLab, npm, Stripe, Slack,
  Square, Shopify, PyPI, Postman, Telegram, Discord, Mailchimp, Twilio, private
  keys, JWTs, …
- a **broad keyword-assignment rule** (~100 provider keywords from
  [h4x0r-dz/Leaked-Credentials](https://github.com/h4x0r-dz/Leaked-Credentials),
  matched as `keyword … = "value"`).
- optional **Shannon-entropy detection** ([detect-secrets](https://github.com/Yelp/detect-secrets)
  / [trufflehog](https://github.com/trufflesecurity/trufflehog) style) for
  unknown/custom secrets that match no regex.

Add your own `SecretRule` entries freely; a `_DENY` list filters obvious
placeholders to cut false positives. (A future option: trufflehog-style **live
verification** — checking a key against the provider API — which is active, so
it'd be opt-in.)

### JS intelligence (leaklens `--js-intel`, deterministic)

`js_intel` mines the same fetched JavaScript for **more attack surface** — things
crawling/fuzzing never reach because they're only referenced inside JS:

- **Endpoints / API paths** (`fetch("/api/v2/users")`) → new `url` assets
- **Hosts / subdomains** referenced in JS → in-scope ones become `subdomain` assets
- **Cloud storage URLs** (S3/GCS/Azure) → `finding(kind="exposure")`
- **Exposed source maps** (`//# sourceMappingURL=…`) → `finding`

It reads the same bodies `js_fetch` cached (no extra requests). Discovered
endpoints/subdomains land in the graph, so triage/AI/report see them (an internal
API or staging host found only in JS becomes a top target). **No LLM, zero
tokens.** Toggle and tune in [config/pipeline.yaml](config/pipeline.yaml):

```yaml
js_intel:
  enabled: true        # turn this step on/off
  max_per_file: 200    # cap endpoints extracted per file
```

(Note: it persists discovered assets but doesn't re-trigger upstream scans in the
same run — by design, to avoid a discovery cycle. Re-run, or `--run-id`, to scan
them deeper.)

### Content-driven subdomains (separate, toggleable)

`content_subdomains` is its **own** step (independent of `js_intel`/`secret_scan`
— turning any one off doesn't affect the others). It reads the same `js_fetch`
bodies and regex-extracts **in-scope subdomains referenced in page content**
(HTML links, `<script src>`, CSP headers, JSON) — both `https://x.apex` and bare
`x.apex` — catching hosts that DNS/vhost brute and passive enum miss because the
name is only *mentioned* somewhere. Saved to
`results/<run_id>/content_subdomains.txt`.

```yaml
content_subdomains:
  enabled: true
```

### Discovery loop (recursive, cross-module)

By default the pipeline is a single pass, so subdomains found late (e.g. by
`content_subdomains` or brute) are recorded but not re-fuzzed that run. Enable the
**discovery loop** to feed them back recursively:

```yaml
# config/pipeline.yaml
discovery:
  loop:
    enabled: false   # turn the loop on/off
    rounds: 2        # max rounds (depth of the feedback loop)
```

When enabled, the **discovery/expansion** stages (asset_discovery, dns_resolve,
alive_detection, vhost_discovery, crawling, historical_urls, tech_fingerprint,
url_probe, js_fetch, content_subdomains) **re-run each round** — so a subdomain
mentioned only in a page gets resolved → crawled → its content re-mined → which
can surface more subdomains, and so on. **Findings/analysis** stages
(dir_bruteforce, secret_scan, js_intel, nuclei_scan, normalization, triage, AI)
run **once at the end** on the full asset set (no duplicate findings, AI billed
once). The loop **stops early** when a round finds no new subdomain, and is
bounded by `rounds`. Default off = single pass (unchanged behaviour).

### Triage — ranked "Top Targets" (deterministic, no LLM)

After recon, the `triage` stage scores every asset by signal and surfaces a
ranked shortlist — so you (and the AI) focus on what matters instead of a flat
URL dump. It runs entirely in the engine: **no LLM, zero tokens.** The approach
is synthesized from [uro](https://github.com/s0md3v/uro) (declutter),
[reNgine](https://github.com/yogeshojha/rengine) (interesting keywords) and
[gf-patterns](https://github.com/1ndianl33t/Gf-Patterns) (per-vuln-class params),
with one rule of its own: **it is non-destructive — nothing is dropped from the
database; noise is only demoted and grouped.**

Signals (configurable weights): nuclei findings, **HTTP-method anomalies**
(e.g. `POST 200` where `GET 403`) and dangerous methods (PUT/DELETE/TRACE…),
**parameters tagged by likely vuln class** (sqli/lfi/ssrf/redirect/xss/idor),
interesting path keywords (`admin`, `api`, `upload`, `.git`…), and auth-protected
statuses (401/403). Catch-all clusters (many URLs sharing status+length) and
static assets are demoted/collapsed — **but never** if the URL carries real
signal (a finding, a non-GET method, a vuln-class param, or a keyword).

Output:
- `results/<run_id>/triage.txt` — human-readable ranked list (for quick tracking)
- `results/<run_id>/triage.json` — full structured ranking (nothing dropped)
- a **"Top Targets"** section at the top of `report.md` / `report.html` / `report.json`

Configure in [config/pipeline.yaml](config/pipeline.yaml) under `triage`:

```yaml
triage:
  top_n: 25              # how many ranked targets to surface in the shortlist
  cluster_threshold: 5  # >= N URLs sharing host+status+length => catch-all noise
  # weights: { method_anomaly: 60, param_vuln_class: 35, catch_all: -50, ... }
```

### Curated AI context (token control)

The AI stages don't get the whole graph dumped at them — by default they receive
only the **triage shortlist** (top-N ranked targets + guaranteed method/param
leads + their 1-hop neighbors), with each node annotated with its triage
score/tags/reasons. On a 400-URL scope this is ~**98% fewer tokens** than the full
graph, with no loss of signal (the high-value endpoints are guaranteed in). The
deterministic engine decides what's interesting; the agent only reasons over it.

**Sharing the budget across subdomains** — `context_scope` decides how the
shortlist is split when the target has many subdomains:
- `global` — one pooled ranking; the top-N best assets across **all** hosts. A
  noisy subdomain can crowd out quiet ones.
- `per_host` — fair coverage; every live host root (optional) + each subdomain's
  top-K URLs, round-robined so quiet subdomains are still represented.

Guaranteed leads (method anomalies, vuln-class params) from **every** subdomain
are always included regardless of scope. `context_max_nodes` is the hard ceiling
either way.

Configure in [config/ai.yaml](config/ai.yaml):

```yaml
context: curated                  # curated (default) | full
context_scope: global            # global | per_host
context_top_n: 25                # GLOBAL: total ranked targets across all hosts
context_per_host: 5              # PER_HOST: top URLs kept per subdomain
context_include_host_roots: true # PER_HOST: always include every live host root
context_max_nodes: 60            # hard ceiling on nodes sent (incl. neighbors)
```

Falls back to the full graph automatically when no triage ranking exists (e.g.
`--run-id` on an older run), or set `context: full` to send everything.

### Prompt versions (A/B-selectable)

The AI stages' prompts are versioned so several sets can coexist and be swapped
without code changes. Pick one in [config/ai.yaml](config/ai.yaml):

```yaml
prompt_version: v1   # v1 = original; v2 = research-tuned (see below)
```

- **v1** — [prompts/web/recon_intel.md](prompts/web/recon_intel.md), [pentest.md](prompts/web/pentest.md)
- **v2** — [prompts/web/v2/](prompts/web/v2/): stronger role, per-vuln-class
  playbook tied to the `_triage` tags, explicit severity/confidence rubric, a
  few-shot example, and an anti-prompt-injection guardrail (treats graph data as
  untrusted) — synthesized from [Vulnhuntr](https://github.com/protectai/vulnhuntr)
  and [PentestGPT](https://github.com/GreyDGL/PentestGPT) prompt practice.

Add more by creating `prompts/web/<version>/<name>.md` and setting
`prompt_version`. Both sets emit the same JSON schema, so they're drop-in.

### DNS resolution (dnsx)

`dns_resolve` runs **dnsx** (after passive enum + vhost fuzz, before the HTTP
probe) and does two things in one pass:

1. **Resolve** the discovered subdomains — attach their **IP(s)**, flag
   **`internal`** hosts (RFC1918/loopback — unreachable from outside; kept as
   intel, not pentested), and **filter wildcard DNS** (`-wd`).
2. **DNS brute-force** — generate `word.<apex>` from a wordlist and resolve them
   too (the active brute the tool otherwise lacks). Only names that actually
   resolve become subdomains. This is where AI-generated candidates plug in later.

The resolved summary is saved to **`results/<run_id>/dns_resolve.txt`** (host →
IPs, `[internal]` flagged). `alive_detection` then probes only the reachable
ones (seed targets always probed). Configure in
[config/pipeline.yaml](config/pipeline.yaml):

```yaml
dns_resolve:
  wildcard_filter: true
  # resolvers: ["1.1.1.1", "8.8.8.8"]   # omit => OS resolver (/etc/resolv.conf)
  brute:
    enabled: true
    wordlist: wordlists/dns/subdomains.txt   # swap for a bigger list anytime
    # max_candidates: 100000
alive_detection:
  skip_internal: true     # don't HTTP-probe internal-only hosts (kept as intel)
```

dnsx is a [ProjectDiscovery](https://github.com/projectdiscovery/dnsx) Go binary
(`go install …/dnsx/cmd/dnsx@latest`). If it's not installed the stage simply
**skips** (the rest of the pipeline runs).

**Resolvers.** dnsx defaults to *public* resolvers (1.1.1.1/8.8.8.8); on networks
that block outbound UDP 53 to those it silently resolves **nothing** (while httpx,
which uses the OS resolver, still works — so hosts look unresolved). To avoid this,
`dns_resolve` and `permutation` point dnsx at the **system resolver** from
`/etc/resolv.conf` by default. Override with `dns_resolve.resolvers` (a list); set
it to `[]` to fall back to dnsx's own defaults.

A host whose DNS returns a public IP **and** internal RFC1918 IPs (e.g. a GSLB
leaking `10.x`) is treated as **reachable** (still probed); the leaked internal
IPs are recorded under the asset's `internal_ips` as intel. Only hosts that
resolve to *exclusively* private IPs are flagged `internal`.

**Network position (`dns_resolve.prefer`).** Where you run from decides which IPs
are reachable: from the internet only public IPs route, from inside the network
internal IPs do too. This one knob is honoured by `alive_detection` (which hosts
to probe) and `vhost_discovery` (which IPs to fuzz) — and since dir-brute runs on
probed hosts, internal-only hosts then get fuzzed too:

| `prefer`   | internal-only hosts | host with public **and** internal IPs |
|---|---|---|
| `public` *(default)* | skipped (kept as intel) | fuzz the **public** IP |
| `internal` | **probed/fuzzed** | focus the **internal** IP |
| `both` | **probed/fuzzed** | use **all** IPs |

So to test from inside the network (internal hosts in scope), set
`dns_resolve.prefer: internal` (or `both`). The legacy `alive_detection.skip_internal`
still applies under `prefer: public` (set it `false` to probe internal-only hosts
without switching position).

`permutation` then goes beyond flat brute: it runs
[alterx](https://github.com/projectdiscovery/alterx) to **mutate the naming
patterns already in use** — given `api`/`dev`/`admin` it generates `api-dev`,
`dev-api`, `api2`, `admin-uat`, … — and resolves the candidates with dnsx, keeping
only names that resolve (with IP + `internal` flag, wildcard noise dropped).
Unlike dns_resolve, **both alterx and dnsx are required** — a missing binary
**fails** the stage. It only runs on a wildcard scope. The new names are crawled
and probed only when `discovery.loop` is enabled; otherwise they're recorded for
the report/AI. Saved to `results/<run_id>/permutation.txt`. Configure:

```yaml
permutation:
  enabled: true
  max_candidates: 5000   # cap candidates sent to dnsx
```

**AI seam.** Both `dns_resolve.brute` and `permutation` also read
`results/<run_id>/ai_subwords.txt` (and `dir_bruteforce` reads
`ai_dirwords.txt`) if present, folding those entries into their candidates. No
file → no effect, so the seam is inert until a (future) AI stage writes it — the
deterministic modules don't change when AI candidate generation is added.

`vhost_discovery` then fuzzes `Host: FUZZ.<apex>` over the **IPs dnsx
discovered** (deduped, internal skipped, capped by `max_ips`) plus the apex
itself, to find **DNS-less vhosts** (sites served on an IP with no DNS record).
A match is already live, so it's registered directly as a `host` (no second
probe). It only runs when the scope enumerates (wildcard). Saved to
`results/<run_id>/vhost.txt`. Configure:

```yaml
vhost_discovery:
  enabled: true
  schemes: [https, http]
  auto_calibrate: true   # ffuf -ac: drop catch-all false positives
  max_ips: 50
```

**Scope rule:** subdomain brute (`dns_resolve.brute`), `permutation` and
`vhost_discovery` only run when the scope uses a wildcard (`*.domain`); an
explicit exact-host scope skips all three — only the given hosts are touched.

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
