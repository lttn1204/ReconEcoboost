"""Deterministic parameter-name mining — candidate params from JS + URLs (no LLM).

Feeds param_discovery's wordlist (Phase 2). Regex-only so there's no hallucination
(an AI stage handles extrapolation separately, via the ``ai_params`` seam).

Mining identifiers (``var``/``let``/``const`` / every object key) out of MINIFIED
JS bundles was tried and abandoned — it's ~99% noise (internal vars like ``_buffer``,
constants like ``AUTO``, and ternary ``a ? b : c`` mis-read as ``?b=`` query params).
Instead we mine only HIGH-PRECISION signals:

* :func:`mine_js_params` — query params from quoted **URL-like strings** in JS
  (``"/api/x?foo=1&bar=2"``) plus keys of ``params``/``data``/``query``/``body``
  object literals near an HTTP call. Both avoid the minifier-noise trap.
* :func:`query_param_names` — parameter *names* already present on observed URLs
  (gau/katana/dir-fuzz). Pooled across endpoints these enable cross-pollination
  (a param seen on endpoint A becomes a candidate tested on endpoint B by arjun).
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

# Quoted string that looks like a URL/path AND carries a query: '/x?a=1', "http://h/y?b=2".
_QUOTED_URL_RE = re.compile(r"""['"`]((?:https?://|/)[^'"`\s]*\?[^'"`\s]+)['"`]""")
# `params:{...}` / `data:{...}` / `query:{...}` / `body:{...}` object literals (one level).
_HTTP_OBJ_RE = re.compile(r"(?:params|data|query|body)\s*:\s*\{([^{}]{0,400})\}")
# An object key inside such a literal.
_OBJ_KEY_RE = re.compile(r"([A-Za-z_][\w]{1,39})\s*:")

_MAX_LEN = 40
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_NAME_RE = re.compile(r"\A[A-Za-z_][\w.-]*\Z")


def _valid(name: str) -> bool:
    """A plausible parameter name: has a letter, not a digit/hash, sane length."""
    if not name or len(name) > _MAX_LEN:
        return False
    if not _NAME_RE.match(name):
        return False
    if name.isdigit():
        return False
    if len(name) >= 24 and _HEX_RE.match(name):   # 50db0456…-style hash, not a param
        return False
    return any(c.isalpha() for c in name)


def mine_js_params(text: str) -> set[str]:
    """Extract candidate parameter names from one JS/JSON body (high precision)."""
    if not text:
        return set()
    found: set[str] = set()
    # 1) query params inside quoted URL strings
    for m in _QUOTED_URL_RE.finditer(text):
        query = m.group(1).split("?", 1)[1]
        for name in parse_qs(query, keep_blank_values=True):
            if _valid(name):
                found.add(name)
    # 2) keys of params/data/query/body object literals near an HTTP call
    for m in _HTTP_OBJ_RE.finditer(text):
        for k in _OBJ_KEY_RE.finditer(m.group(1)):
            name = k.group(1)
            if _valid(name):
                found.add(name)
    return found


def query_param_names(url: str) -> set[str]:
    """Parameter names present in a URL's query string (filtered for noise)."""
    if not url or "?" not in url:
        return set()
    try:
        query = urlsplit(url).query
    except ValueError:
        return set()
    return {k for k in parse_qs(query, keep_blank_values=True) if _valid(k)}
