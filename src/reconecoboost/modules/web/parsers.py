"""Parsers for the v1 web tools.

Each is a pure function of raw tool output -> ``ParsedRecord`` list, registered
with the default parser registry. Structured tool output (JSON/JSONL) is
preferred over scraping human text wherever the tool offers it (architecture
doc 08). Relation hints (e.g. url -> belongs_to -> host) are attached to records
so the Normalizer/graph can wire the knowledge graph.
"""

from __future__ import annotations

import ipaddress
import json

from ...core.entities import Relation
from ...engine.parser import ParsedRecord, Parser, register_parser
from ..base import host_of, origin_of


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private  # covers RFC1918 + loopback + link-local
    except ValueError:
        return False


def _json_lines(raw: str):
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


@register_parser
class SubfinderParser(Parser):
    """subfinder ``-silent`` output: one subdomain per line."""

    tool = "subfinder"

    def parse(self, raw: str) -> list[ParsedRecord]:
        records = []
        for line in raw.splitlines():
            host = line.strip()
            if not host or host.startswith("#"):
                continue
            records.append(ParsedRecord("subdomain", host, tool="subfinder"))
        return records


@register_parser
class HttpxParser(Parser):
    """httpx ``-json`` output: one JSON object per live host."""

    tool = "httpx"

    def parse(self, raw: str) -> list[ParsedRecord]:
        records = []
        for data in _json_lines(raw):
            url = data.get("url") or data.get("input")
            origin = origin_of(url)
            if origin is None:
                continue
            attrs = {
                key: data[key]
                for key in ("status_code", "title", "webserver", "scheme", "port", "content_length")
                if data.get(key) is not None
            }
            tech = data.get("tech") or data.get("technologies")
            if tech:
                attrs["tech"] = tech

            record = ParsedRecord("host", origin, attributes=attrs, tool="httpx")
            sub = host_of(data.get("input") or url)
            if sub:
                record.relations.append(
                    Relation("subdomain", sub, "resolves_to", "host", origin)
                )
            records.append(record)
        return records


@register_parser
class DnsxParser(Parser):
    """dnsx ``-json -a -resp`` output: resolved hosts with their IP records.

    Enriches the matching ``subdomain`` asset with ``resolved``, ``ip`` and an
    ``internal`` flag (RFC1918/loopback). dnsx only emits resolving hosts, so a
    record here means the name exists in DNS.
    """

    tool = "dnsx"

    def parse(self, raw: str) -> list[ParsedRecord]:
        records = []
        for data in _json_lines(raw):
            host = data.get("host")
            ips = list(data.get("a") or []) + list(data.get("aaaa") or [])
            if not host or not ips:
                continue  # NODATA/NXDOMAIN (no A/AAAA) is not a resolving host
            attrs = {"resolved": True, "ip": ips}
            private = [ip for ip in ips if _is_private_ip(ip)]
            if private and len(private) == len(ips):
                attrs["internal"] = True       # only private IPs -> not externally reachable
            elif private:
                # Mixed: reachable on a public IP but DNS also leaks internal IPs
                # (e.g. a GSLB returning RFC1918). Keep it probable AND flag the leak.
                attrs["internal_ips"] = private
            records.append(ParsedRecord("subdomain", host.strip().lower(), attributes=attrs, tool="dnsx"))
        return records


@register_parser
class HttpxUrlParser(Parser):
    """httpx ``-json`` output when probing URLs (not subdomains).

    Emits a ``url`` record keyed by the fed input, so the status/size/tech merge
    into the existing URL asset (recording its liveness for downstream scanning).
    """

    tool = "httpx_url"

    def parse(self, raw: str) -> list[ParsedRecord]:
        records = []
        for data in _json_lines(raw):
            key = data.get("input") or data.get("url")
            if not key:
                continue
            attrs = {
                k: data[k]
                for k in ("status_code", "content_length", "title", "webserver", "scheme")
                if data.get(k) is not None
            }
            tech = data.get("tech") or data.get("technologies")
            if tech:
                attrs["tech"] = tech
            records.append(ParsedRecord("url", key, attributes=attrs, tool="httpx"))
        return records


@register_parser
class KatanaParser(Parser):
    """katana ``-jsonl`` output: one JSON object per crawled endpoint."""

    tool = "katana"

    def parse(self, raw: str) -> list[ParsedRecord]:
        records = []
        for data in _json_lines(raw):
            endpoint = (
                data.get("endpoint")
                or (data.get("request") or {}).get("endpoint")
                or data.get("url")
            )
            if not endpoint:
                continue
            record = ParsedRecord("url", endpoint, tool="katana")
            origin = origin_of(endpoint)
            if origin:
                record.relations.append(
                    Relation("url", endpoint, "belongs_to", "host", origin)
                )
            records.append(record)
        return records


@register_parser
class GauParser(Parser):
    """gau output: one URL per line."""

    tool = "gau"

    def parse(self, raw: str) -> list[ParsedRecord]:
        records = []
        for line in raw.splitlines():
            url = line.strip()
            if not url or "://" not in url:
                continue
            record = ParsedRecord("url", url, tool="gau")
            origin = origin_of(url)
            if origin:
                record.relations.append(Relation("url", url, "belongs_to", "host", origin))
            records.append(record)
        return records


def extract_ffuf_json(raw: str) -> dict | None:
    """Extract ffuf's JSON report from stdout.

    With ``-s`` and ``-o /dev/stdout``, ffuf writes the matched keywords (one per
    line) AND the JSON report to stdout, concatenated. The report is a single
    JSON object; isolate it from the first ``{"`` so the leading keyword lines
    don't break json parsing.
    """
    if not raw:
        return None
    start = raw.find('{"')
    if start == -1:
        start = raw.find("{")
    if start == -1:
        return None
    try:
        parsed = json.loads(raw[start:])
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


@register_parser
class FfufParser(Parser):
    """ffuf ``-of json`` output: a JSON object with a ``results`` array."""

    tool = "ffuf"

    def parse(self, raw: str) -> list[ParsedRecord]:
        data = extract_ffuf_json(raw)
        if data is None:
            return []

        method = (data.get("config") or {}).get("method", "GET")
        records = []
        for item in data.get("results", []):
            url = item.get("url")
            if not url:
                continue
            attrs = {
                key: item[key]
                for key in ("status", "length", "words", "lines",
                            "content-type", "redirectlocation")
                if item.get(key) not in (None, "")
            }
            attrs["method"] = method
            record = ParsedRecord("url", url, attributes=attrs, tool="ffuf")
            origin = origin_of(url)
            if origin:
                record.relations.append(Relation("url", url, "belongs_to", "host", origin))
            records.append(record)
        return records


@register_parser
class FeroxbusterParser(Parser):
    """feroxbuster ``--json --silent`` output: one JSON object per event.

    Only ``type == "response"`` lines are real hits. Fields are mapped to the same
    attribute names the ffuf parser used (status/length/words/redirectlocation +
    method) so the existing per-method folding + per-host result files still work.
    Recursion is handled by feroxbuster itself; recursed hits arrive as ordinary
    response lines (deeper paths), so no extra handling is needed here.
    """

    tool = "feroxbuster"

    def parse(self, raw: str) -> list[ParsedRecord]:
        records = []
        for data in _json_lines(raw):
            if data.get("type") != "response":
                continue
            url = data.get("url")
            if not url:
                continue
            attrs = {"method": data.get("method", "GET")}
            if data.get("status") is not None:
                attrs["status"] = data["status"]
            if data.get("content_length") is not None:
                attrs["length"] = data["content_length"]
            if data.get("word_count") is not None:
                attrs["words"] = data["word_count"]
            location = (data.get("headers") or {}).get("location")
            if location:
                attrs["redirectlocation"] = location
            record = ParsedRecord("url", url, attributes=attrs, tool="feroxbuster")
            origin = origin_of(url)
            if origin:
                record.relations.append(Relation("url", url, "belongs_to", "host", origin))
            records.append(record)
        return records


@register_parser
class FfufVhostParser(Parser):
    """ffuf vhost output: each matched result's FUZZ keyword is a vhost prefix.

    The full hostname (``FUZZ.<domain>``) is reconstructed by the module's
    ``refine_records`` (the parser only has the keyword, not the domain).
    """

    tool = "ffuf_vhost"

    def parse(self, raw: str) -> list[ParsedRecord]:
        data = extract_ffuf_json(raw)
        if data is None:
            return []
        records = []
        for item in data.get("results", []):
            fuzz = (item.get("input") or {}).get("FUZZ")
            if not fuzz:
                continue
            attrs = {
                key: item[key]
                for key in ("status", "length", "words")
                if item.get(key) is not None
            }
            records.append(ParsedRecord("subdomain", fuzz, attributes=attrs, tool="ffuf_vhost"))
        return records


def bake_params(url: str, params: list[str]) -> str:
    """Append discovered param names to a URL's query string.

    A placeholder value (``=1``) is used because triage's ``param_keys`` (and
    ``parse_qs`` generally) DROP blank-valued params — ``?id=`` would be invisible.
    The clean param-name list is kept in ``discovered_params`` for the report.
    """
    if not params:
        return url
    sep = "&" if "?" in url else "?"
    return url + sep + "&".join(f"{p}=1" for p in params)


@register_parser
class ArjunParser(Parser):
    """arjun ``-oJ`` JSON output: ``{url: {method, params:[...], headers}}``.

    Each entry's discovered params are baked into the URL's query string so the
    existing triage param scoring (param_keys / param_vuln_classes) picks them up
    with no triage change. The raw param-name list + method are kept on attributes.
    """

    tool = "arjun"

    def parse(self, raw: str) -> list[ParsedRecord]:
        raw = (raw or "").strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []

        records = []
        for url, info in data.items():
            if not isinstance(info, dict):
                continue
            params = [str(p) for p in (info.get("params") or []) if p]
            if not params:
                continue
            method = info.get("method", "GET")
            baked = bake_params(url, params)
            attrs = {"discovered_params": params, "param_method": method}
            record = ParsedRecord("url", baked, attributes=attrs, tool="arjun")
            origin = origin_of(baked) or origin_of(url)
            if origin:
                record.relations.append(Relation("url", baked, "belongs_to", "host", origin))
            records.append(record)
        return records


@register_parser
class WhatwebParser(Parser):
    """whatweb ``--log-json`` output: array of targets with detected plugins."""

    tool = "whatweb"

    def parse(self, raw: str) -> list[ParsedRecord]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = list(_json_lines(raw))
        if isinstance(data, dict):
            data = [data]

        records = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            origin = origin_of(entry.get("target"))
            plugins = entry.get("plugins") or {}
            for name, info in plugins.items():
                attrs = {}
                version = info.get("version") if isinstance(info, dict) else None
                if version:
                    attrs["version"] = version[0] if isinstance(version, list) and version else version
                record = ParsedRecord("technology", name, attributes=attrs, tool="whatweb")
                if origin:
                    record.relations.append(
                        Relation("host", origin, "uses", "technology", name)
                    )
                records.append(record)
        return records
