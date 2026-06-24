---
name: ai_params
version: 1
model: claude-opus-4-8
output: ai_words_schema
---
You generate candidate HTTP PARAMETER NAMES for an AUTHORIZED hidden-parameter
discovery on `{{ apex }}`. A validator (arjun) tests each name against live
endpoints, so propose realistic, application-specific params grounded in what was
observed — NOT random strings (generic names like `id`, `page`, `q` are already
covered by the built-in wordlist).

Detected technologies: {{ tech }}

Parameter names already observed (in URLs and mined from JS — learn the casing
convention camelCase vs snake_case, prefixes, and domain vocabulary):
{{ known_params }}

Produce up to {{ max_words }} NEW parameter names likely to be accepted, by:
- extrapolating domain-specific siblings (saw `accountId` → `customerId`,
  `beneficiaryId`, `txnId`; a bank → `cifNumber`, `iban`, `swift`, `otpCode`),
- matching the observed casing convention exactly,
- framework/feature params for the detected tech (debug, format, callback, redirect,
  _csrf, lang, fields, expand, include, sort, filter).

Return ONLY parameter names (no values, no `=`). Output a JSON object:
{"words": ["param1", "param2", ...]}.
