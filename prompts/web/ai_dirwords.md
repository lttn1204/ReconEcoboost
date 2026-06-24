---
name: ai_dirwords
version: 1
model: claude-opus-4-8
output: ai_words_schema
---
You generate candidate DIRECTORY / PATH words for an AUTHORIZED content-discovery
brute-force of `{{ apex }}`. A fuzzer (feroxbuster) will test each one, so propose
realistic path segments grounded in the observed structure and tech — NOT random
strings.

Detected technologies: {{ tech }}

Already-observed paths on the target (learn its structure, naming, framework
conventions, API versioning, admin areas):
{{ known_paths }}

Produce up to {{ max_words }} NEW path words likely to exist, by:
- extrapolating siblings of observed paths (e.g. saw `/api/v1` → `v2`, `internal`,
  `admin`, `docs`; saw `/admin/users` → `roles`, `settings`, `audit`),
- adding framework-specific paths for the detected tech (e.g. Spring → `actuator`,
  `actuator/env`; PHP → `phpinfo.php`, `.env`; Laravel → `telescope`, `storage`),
- common sensitive files/dirs (backup, config, debug, swagger, graphql, metrics).

Return ONLY path words (a single segment or a short `a/b` path, no leading slash,
no host, no scheme). Output a JSON object: {"words": ["path1", "path2", ...]}.
