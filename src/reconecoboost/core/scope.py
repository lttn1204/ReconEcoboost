"""Engagement scope.

Scope is part of the read-only core of the :class:`~reconecoboost.core.context.Context`
and is the Context side of the Context+CommandExecutor enforcement chokepoint.

Pattern syntax (host matching):

    example.com      exact host only — the apex, NOT its subdomains
    *.example.com    any subdomain of example.com (a.example.com, x.y.example.com),
                     but NOT the apex example.com itself

To include the apex *and* all subdomains, list both. ``out_of_scope`` takes
precedence over ``in_scope``. An empty ``in_scope`` means "everything not
explicitly excluded" (convenient for a single seed target).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Scope:
    """In-scope / out-of-scope rules for a run."""

    #: Seed targets passed to discovery (e.g. subfinder). Always permitted to run.
    targets: list[str] = field(default_factory=list)
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    @staticmethod
    def _match(host: str, pattern: str) -> bool:
        host = host.lower().rstrip(".")
        pattern = pattern.lower().rstrip(".")
        if pattern.startswith("*."):
            # "*.example.com" -> ".example.com": subdomains only, not the apex.
            return host.endswith(pattern[1:])
        return host == pattern

    def is_allowed(self, value: str | None) -> bool:
        """Return whether ``value`` (a hostname) is permitted by this scope.

        ``out_of_scope`` always wins. The explicit seed targets are always in
        scope (you asked to scan them) — so `*.example.com` scope still scans
        `example.com` itself when it's the target. Otherwise `in_scope` applies
        (empty = allow anything not excluded).
        """
        if not value:
            return False
        host = value
        if any(self._match(host, p) for p in self.out_of_scope):
            return False
        if any(self._match(host, t) for t in self.targets):
            return True
        if not self.in_scope:
            return True
        return any(self._match(host, p) for p in self.in_scope)
