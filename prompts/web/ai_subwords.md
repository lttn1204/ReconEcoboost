---
name: ai_subwords
version: 1
model: claude-opus-4-8
output: ai_words_schema
---
You generate candidate SUBDOMAIN LABELS for an AUTHORIZED reconnaissance of
`{{ apex }}`. A DNS resolver will test each candidate — invalid guesses cost
nothing — so propose realistic labels grounded in the observed naming, NOT random
strings.

Already-observed subdomain labels (the part before `.{{ apex }}` — learn their
conventions: prefixes, environment tags, product names, separators):
{{ known_subs }}

Produce up to {{ max_words }} NEW labels likely to exist, by:
- extrapolating environment/stage variants (dev, uat, staging, qa, test, sit, prod),
- pluralizing/abbreviating product names already seen,
- combining observed prefixes with common service names (api, admin, vpn, mail,
  auth, sso, gateway, internal, portal, mobile),
- applying the org's domain context (e.g. a bank: ebanking, ib, corp, payment).

Return ONLY bare labels — no `.{{ apex }}` suffix, no scheme, no dots. Output a
JSON object: {"words": ["label1", "label2", ...]}.
