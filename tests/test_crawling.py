"""Crawling (katana) command bounds — guards against unbounded-crawl OOM."""

from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.engine import ToolHandle
from reconecoboost.modules.web.crawling import Crawling


def _ctx(pipeline=None):
    return Context(domain=Domain.WEB, scope=Scope(targets=["example.com"]),
                   config=Config(pipeline=pipeline or {}))


def _tool():
    return ToolHandle(name="katana", binary="katana", path="/usr/bin/katana")


def test_crawling_is_bounded_by_default():
    argv = Crawling().command(_tool(), "https://example.com", _ctx()).argv
    # the OOM guards must be present by default
    assert "-mdp" in argv and argv[argv.index("-mdp") + 1] == "2000"
    assert "-ct" in argv and argv[argv.index("-ct") + 1] == "5m"
    assert "-d" in argv and argv[argv.index("-d") + 1] == "3"


def test_crawling_bounds_are_configurable():
    pipeline = {"crawling": {"depth": 1, "max_domain_pages": 50,
                             "crawl_duration": "30s", "field_scope": "fqdn",
                             "js_crawl": True}}
    argv = Crawling().command(_tool(), "https://example.com", _ctx(pipeline)).argv
    assert argv[argv.index("-d") + 1] == "1"
    assert argv[argv.index("-mdp") + 1] == "50"
    assert argv[argv.index("-ct") + 1] == "30s"
    assert argv[argv.index("-fs") + 1] == "fqdn"
    assert "-jc" in argv


def test_crawling_caps_can_be_disabled():
    pipeline = {"crawling": {"max_domain_pages": 0, "crawl_duration": "", "depth": 0}}
    argv = Crawling().command(_tool(), "https://example.com", _ctx(pipeline)).argv
    assert "-mdp" not in argv and "-ct" not in argv and "-d" not in argv
