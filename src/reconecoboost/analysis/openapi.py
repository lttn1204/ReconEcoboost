"""Deterministic OpenAPI/Swagger parsing + GraphQL detection (no LLM).

Pure helpers for the api_discovery module (Phase 3). An exposed API spec is a
goldmine: it enumerates every endpoint, method and parameter the backend accepts —
far more than HTML crawling surfaces.
"""

from __future__ import annotations

import json

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def extract_http_body(raw: str) -> str:
    """Return the body from a raw HTTP response (headers + CRLF CRLF + body).

    httpx ``-irr`` stores the full raw response; for JSON parsing we want the body
    only. Falls back to the whole string if no header/body separator is present.
    """
    if not raw:
        return ""
    for sep in ("\r\n\r\n", "\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[idx + len(sep):]
    return raw


def parse_openapi(body: str) -> list[dict] | None:
    """Parse an OpenAPI/Swagger JSON body into endpoint records.

    Returns ``None`` if the body isn't a recognizable spec. Each record is
    ``{"path": str, "method": str, "params": [name, ...]}``. The base path
    (swagger ``basePath`` / openapi ``servers``) is prepended when present.
    """
    body = (body or "").strip()
    if not body:
        return None
    try:
        spec = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(spec, dict):
        return None
    paths = spec.get("paths")
    # Must look like a spec: an openapi/swagger marker AND a paths object.
    if not isinstance(paths, dict) or not (spec.get("openapi") or spec.get("swagger")):
        return None

    base = _base_path(spec)
    out: list[dict] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = _param_names(item.get("parameters"))   # path-level params
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            names = sorted(set(shared) | _param_names(op.get("parameters"))
                           | _body_param_names(op.get("requestBody")))
            out.append({"path": base + str(path), "method": method.upper(), "params": names})
    return out or None


def _base_path(spec: dict) -> str:
    base = spec.get("basePath")               # OpenAPI 2.0
    if isinstance(base, str) and base != "/":
        return base.rstrip("/")
    servers = spec.get("servers")             # OpenAPI 3.x
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = str(servers[0].get("url", ""))
        # keep only a leading path component (ignore absolute server URLs/hosts)
        if url.startswith("/"):
            return url.rstrip("/")
    return ""


def _param_names(parameters) -> set[str]:
    names: set[str] = set()
    if isinstance(parameters, list):
        for p in parameters:
            if isinstance(p, dict) and p.get("name"):
                names.add(str(p["name"]))
    return names


def _body_param_names(request_body) -> set[str]:
    """Top-level property names from a requestBody JSON schema."""
    names: set[str] = set()
    if not isinstance(request_body, dict):
        return names
    content = request_body.get("content")
    if not isinstance(content, dict):
        return names
    for media in content.values():
        schema = (media or {}).get("schema") if isinstance(media, dict) else None
        props = (schema or {}).get("properties") if isinstance(schema, dict) else None
        if isinstance(props, dict):
            names.update(str(k) for k in props)
    return names


def looks_like_graphql(body: str, status: int | None) -> bool:
    """Heuristic: does this response look like a GraphQL endpoint?

    Probed only against known GraphQL paths, so the body just needs to confirm.
    The bare word "graphql" is too weak (docs pages mention it), so we require a
    GraphQL-specific signature: an introspection schema, a known "no query" error,
    or a JSON ``errors`` array referencing a query/graphql.
    """
    low = (body or "").lower()
    if "__schema" in low:
        return True
    markers = ("must provide query string", "must provide an operation",
               "query is required", "no query string", "graphql query",
               "operationname", "syntax error: unexpected")
    if any(m in low for m in markers):
        return True
    if '"errors"' in low and ("query" in low or "graphql" in low):
        return True
    return False
