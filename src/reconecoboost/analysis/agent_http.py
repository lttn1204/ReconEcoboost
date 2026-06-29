"""Guarded HTTP client — the ONLY way the agentic AI pentest touches a live target.

This is a second network-egress path besides the CommandExecutor, so it carries its
own enforcement (it never runs a subprocess; it speaks HTTP in-process). Every request
is refused unless it passes ALL guardrails:

- **scope**   — the host must satisfy ``scope.is_allowed`` (out-of-scope = refused).
- **method**  — must be in the allowlist (default GET + POST; destructive verbs refused).
- **payload** — obviously destructive URLs/bodies are refused (best-effort denylist).
- **budget**  — a hard cap on total requests per run; rate-limited between calls.

Refused requests return a result dict with ``refused`` set and never hit the network.
Every sent request returns the full request+response so findings carry real evidence.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlsplit

from ..logging.setup import get_logger

# Best-effort destructive-payload denylist (substring, case-insensitive). The agent is
# also instructed to stay non-destructive; this is defence in depth, not the only line.
_DESTRUCTIVE = re.compile(
    r"(drop\s+table|delete\s+from|truncate\s+table|rm\s+-rf|;\s*rm\s|shutdown|"
    r"mkfs|format\s+c:|--no-preserve-root|>\s*/dev/sd)",
    re.IGNORECASE,
)
_SAFE_SCHEMES = {"http", "https"}


class AgentHttp:
    """Scope-enforced, non-destructive, budget-capped HTTP client."""

    def __init__(
        self,
        scope,
        *,
        allowed_methods: list[str] | None = None,
        max_requests: int = 120,
        rate_per_s: float = 3.0,
        timeout_s: float = 15.0,
        max_body_bytes: int = 20000,
        run_id: str | None = None,
    ) -> None:
        self.scope = scope
        self.allowed = {m.upper() for m in (allowed_methods or ["GET", "POST"])}
        self.max_requests = int(max_requests)
        self.min_interval = 1.0 / rate_per_s if rate_per_s and rate_per_s > 0 else 0.0
        self.timeout_s = timeout_s
        self.max_body_bytes = int(max_body_bytes)
        self.count = 0
        self._last = 0.0
        self._log = get_logger("module.ai_pentest.http", run_id=run_id)
        self._client = None  # lazily created (test seam: inject a transport)

    # -- public ---------------------------------------------------------------
    @property
    def budget_left(self) -> int:
        return max(0, self.max_requests - self.count)

    def request(
        self, method: str, url: str,
        headers: dict[str, str] | None = None, body: str | None = None,
    ) -> dict[str, Any]:
        """Send one guarded request. Returns a result dict (never raises on HTTP)."""
        req = {"method": (method or "GET").upper(), "url": url,
               "headers": headers or {}, "body": body or ""}

        refusal = self._refuse(req)
        if refusal:
            self._log.info("refused %s %s — %s", req["method"], url, refusal)
            return {"ok": False, "refused": refusal, "request": req}

        self._throttle()
        self.count += 1
        try:
            client = self._ensure_client()
            resp = client.request(
                req["method"], url, headers=headers or None,
                content=(body or None) if req["method"] != "GET" else None,
            )
            raw = resp.content[: self.max_body_bytes]
            text = raw.decode(resp.encoding or "utf-8", errors="replace")
            try:
                elapsed_ms = int(resp.elapsed.total_seconds() * 1000)
            except RuntimeError:  # not available (e.g. mock transport)
                elapsed_ms = None
            return {
                "ok": True, "request": req,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "location": resp.headers.get("location"),
                "body": text,
                "body_truncated": len(resp.content) > self.max_body_bytes,
                "elapsed_ms": elapsed_ms,
            }
        except Exception as exc:  # network error — report, don't crash the run
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "request": req}

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    # -- guards ---------------------------------------------------------------
    def _refuse(self, req: dict) -> str | None:
        if self.budget_left <= 0:
            return "request budget exhausted"
        if req["method"] not in self.allowed:
            return f"method {req['method']} not in allowlist {sorted(self.allowed)}"
        parts = urlsplit(req["url"])
        if parts.scheme.lower() not in _SAFE_SCHEMES:
            return f"scheme '{parts.scheme}' not allowed"
        if not parts.hostname:
            return "no host in url"
        if not self._host_allowed(parts.hostname):
            return f"host '{parts.hostname}' is out of scope"
        if _DESTRUCTIVE.search(req["url"]) or _DESTRUCTIVE.search(req["body"]):
            return "destructive payload blocked"
        return None

    @staticmethod
    def _match(host: str, pattern: str) -> bool:
        host, pattern = host.lower().rstrip("."), pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            return host.endswith(pattern[1:])
        return host == pattern

    def _host_allowed(self, host: str) -> bool:
        """STRICTER than Scope.is_allowed: for live traffic an empty in_scope must NOT
        mean "allow everything". The host must explicitly match a target or in_scope
        pattern (and not be out_of_scope)."""
        if any(self._match(host, p) for p in self.scope.out_of_scope):
            return False
        patterns = list(self.scope.targets) + list(self.scope.in_scope)
        return bool(patterns) and any(self._match(host, p) for p in patterns)

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _ensure_client(self):
        if self._client is None:
            import httpx
            self._client = httpx.Client(
                timeout=self.timeout_s, follow_redirects=False,
                verify=False, headers={"User-Agent": "ReconEcoboost-agent/1.0"},
            )
        return self._client
