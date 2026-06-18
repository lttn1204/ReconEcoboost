"""Tests for the parser registry and the Normalizer dedupe/merge behaviour."""

import pytest

from reconecoboost.core.entities import Relation
from reconecoboost.engine import Normalizer, ParsedRecord, Parser, ParserRegistry
from reconecoboost.engine.normalizer import canonical_key


class _DummyParser(Parser):
    tool = "dummy"

    def parse(self, raw):
        return [ParsedRecord(asset_type="subdomain", key=line, tool="dummy")
                for line in raw.splitlines() if line]


def test_registry_register_and_get():
    registry = ParserRegistry()
    registry.register(_DummyParser())
    assert registry.has("dummy")
    parsed = registry.get("dummy").parse("a.example.com\nb.example.com")
    assert [p.key for p in parsed] == ["a.example.com", "b.example.com"]


def test_registry_rejects_unnamed_parser():
    class Nameless(Parser):
        def parse(self, raw):
            return []

    with pytest.raises(ValueError):
        ParserRegistry().register(Nameless())


def test_canonical_key_lowercases_hosts():
    assert canonical_key("host", "WWW.Example.COM.") == "www.example.com"
    assert canonical_key("url", "https://Example.com/A") == "https://Example.com/A"


def test_normalizer_dedupes_and_merges_sources():
    records = [
        ParsedRecord("url", "https://x/a", attributes={"status": 200}, tool="katana"),
        ParsedRecord("url", "https://x/a", attributes={"length": 10}, tool="gau"),
    ]
    result = Normalizer().normalize(records)
    assert len(result.entities) == 1
    entity = result.entities[0]
    assert entity.attributes == {"status": 200, "length": 10}
    assert {s.tool for s in entity.sources} == {"katana", "gau"}


def test_normalizer_dedupes_relations():
    rel = Relation("host", "h", "serves", "url", "u")
    result = Normalizer().normalize([], relations=[rel, rel])
    assert len(result.relations) == 1
