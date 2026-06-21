"""Extract in-scope subdomains referenced in fetched page content.

Pure regex over text (HTML / JS / JSON / CSP headers), scoped to the target
apex(es). Finds subdomains that DNS brute, vhost fuzzing and passive enum miss
because the name is only *mentioned* in a page (a link, ``<script src>``, a CSP
``Content-Security-Policy`` entry, a JSON config). No LLM.
"""

from __future__ import annotations

import re


def extract_subdomains(text: str, apexes: list[str]) -> set[str]:
    """Return hostnames in ``text`` that are sub-labels of any given apex."""
    found: set[str] = set()
    for apex in apexes:
        if not apex:
            continue
        # one-or-more labels, then the apex; bounded so we don't match a larger
        # domain (e.g. apex "example.com" won't match "notexample.com").
        pattern = re.compile(
            r"(?<![\w.-])((?:[a-z0-9_-]+\.)+" + re.escape(apex) + r")(?![\w.-])",
            re.IGNORECASE,
        )
        for match in pattern.finditer(text):
            host = match.group(1).lower().rstrip(".")
            if host and host != apex.lower():
                found.add(host)
    return found
