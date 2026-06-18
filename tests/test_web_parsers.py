"""Tests for the v1 web parsers against representative tool output."""

import json

import reconecoboost.modules.web  # noqa: F401  (registers parsers)
from reconecoboost.engine import PARSERS


def test_subfinder_parser():
    parser = PARSERS.get("subfinder")
    records = parser.parse("a.example.com\n# comment\n\nb.example.com\n")
    assert [r.key for r in records] == ["a.example.com", "b.example.com"]
    assert all(r.asset_type == "subdomain" for r in records)


def test_httpx_parser_emits_host_and_relation():
    line = json.dumps(
        {"input": "a.example.com", "url": "https://a.example.com",
         "status_code": 200, "title": "Hi", "tech": ["nginx"]}
    )
    records = PARSERS.get("httpx").parse(line)
    assert len(records) == 1
    rec = records[0]
    assert rec.asset_type == "host"
    assert rec.key == "https://a.example.com"
    assert rec.attributes["status_code"] == 200
    assert rec.relations[0].rel_type == "resolves_to"
    assert rec.relations[0].src_key == "a.example.com"


def test_katana_parser_request_endpoint():
    line = json.dumps({"request": {"endpoint": "https://a.example.com/login"}})
    records = PARSERS.get("katana").parse(line)
    assert records[0].asset_type == "url"
    assert records[0].key == "https://a.example.com/login"
    assert records[0].relations[0].dst_key == "https://a.example.com"


def test_gau_parser_skips_non_urls():
    records = PARSERS.get("gau").parse("https://a.example.com/x\nnot-a-url\n")
    assert [r.key for r in records] == ["https://a.example.com/x"]


def test_ffuf_parser_results_array():
    raw = json.dumps(
        {"results": [{"url": "https://a.example.com/admin", "status": 200, "length": 12}]}
    )
    records = PARSERS.get("ffuf").parse(raw)
    assert records[0].key == "https://a.example.com/admin"
    assert records[0].attributes["status"] == 200


def test_whatweb_parser_array_with_plugins():
    raw = json.dumps(
        [{"target": "https://a.example.com",
          "plugins": {"nginx": {"version": ["1.25"]}, "PHP": {}}}]
    )
    records = PARSERS.get("whatweb").parse(raw)
    names = {r.key for r in records}
    assert names == {"nginx", "PHP"}
    nginx = next(r for r in records if r.key == "nginx")
    assert nginx.attributes["version"] == "1.25"
    assert nginx.relations[0].rel_type == "uses"
