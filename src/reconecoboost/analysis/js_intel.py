"""Deterministic JS intelligence — mine endpoints/hosts/cloud URLs from JS text.

leaklens-style ``--js-intel``: JavaScript often references API routes and hosts
that crawling/fuzzing never reach. We regex them out of the fetched bodies. Pure
functions, no LLM, no I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Quoted absolute paths: "/api/v2/users" — single leading slash, no spaces.
_ENDPOINT = re.compile(r"""['"](/[A-Za-z0-9_\-./~%]{2,120})['"]""")
# Hosts referenced via an absolute URL.
_HOST = re.compile(r"https?://([A-Za-z0-9](?:[A-Za-z0-9\-.]{0,253}[A-Za-z0-9])?\.[A-Za-z]{2,24})")
# Cloud storage URLs.
_CLOUD = re.compile(
    r"(?:s3://[a-z0-9.\-]{3,}"
    r"|[a-z0-9.\-]{3,}\.s3[.\-][a-z0-9.\-]*amazonaws\.com"
    r"|storage\.googleapis\.com/[\w\-./]+"
    r"|[a-z0-9]{3,}\.blob\.core\.windows\.net)"
)
_SOURCEMAP = re.compile(r"sourceMappingURL=([^\s'\"]+)")

# Paths we don't treat as endpoints (static assets / protocol-relative).
_SKIP_PATH_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
                  ".woff2", ".ttf", ".eot", ".webp", ".mp4", ".mp3", ".map")


@dataclass
class JsIntel:
    endpoints: list[str] = field(default_factory=list)   # absolute paths
    hosts: list[str] = field(default_factory=list)        # referenced hostnames
    cloud: list[str] = field(default_factory=list)         # cloud storage URLs
    sourcemaps: list[str] = field(default_factory=list)    # exposed source maps


def extract(text: str, *, max_endpoints: int = 200) -> JsIntel:
    """Pull endpoints, hosts, cloud URLs and source maps out of JS/JSON text."""
    endpoints: list[str] = []
    seen: set[str] = set()
    for m in _ENDPOINT.finditer(text):
        path = m.group(1)
        if "//" in path or path.lower().endswith(_SKIP_PATH_EXT):
            continue
        if path in seen:
            continue
        seen.add(path)
        endpoints.append(path)
        if len(endpoints) >= max_endpoints:
            break
    hosts = sorted({m.group(1).lower() for m in _HOST.finditer(text)})
    cloud = sorted({m.group(0) for m in _CLOUD.finditer(text)})
    sourcemaps = sorted({m.group(1) for m in _SOURCEMAP.finditer(text) if m.group(1)})
    return JsIntel(endpoints=endpoints, hosts=hosts, cloud=cloud, sourcemaps=sourcemaps)
