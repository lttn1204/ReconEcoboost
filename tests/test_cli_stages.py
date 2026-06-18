"""Tests for AI-mode stage selection in the CLI."""

from types import SimpleNamespace

from reconecoboost.cli.main import (
    _select_stages,
    resolve_ai_mode,
    should_enumerate,
    targets_from_scope,
)

ALL = [
    "asset_discovery", "alive_detection", "crawling", "historical_urls",
    "tech_fingerprint", "dir_bruteforce", "normalization",
    "ai_recon_intel", "ai_pentest",
]


def test_mode_off_drops_all_ai_stages():
    out = _select_stages(None, ALL, "off")
    assert "normalization" in out
    assert "ai_recon_intel" not in out
    assert "ai_pentest" not in out


def test_mode_analyze_keeps_only_intel():
    out = _select_stages(None, ALL, "analyze")
    assert "ai_recon_intel" in out
    assert "ai_pentest" not in out


def test_mode_pentest_keeps_both():
    out = _select_stages(None, ALL, "pentest")
    assert "ai_recon_intel" in out
    assert "ai_pentest" in out


def test_select_respects_profile_subset():
    profile = ["asset_discovery", "ai_recon_intel", "ai_pentest"]
    assert _select_stages(profile, ALL, "analyze") == ["asset_discovery", "ai_recon_intel"]


class _Cfg:
    def __init__(self, mode=None):
        self.ai = {"mode": mode} if mode else {}


def test_resolve_no_ai_wins():
    args = SimpleNamespace(no_ai=True, ai_mode="pentest")
    assert resolve_ai_mode(args, _Cfg("pentest")) == "off"


def test_resolve_cli_overrides_config():
    args = SimpleNamespace(no_ai=False, ai_mode="pentest")
    assert resolve_ai_mode(args, _Cfg("analyze")) == "pentest"


def test_resolve_falls_back_to_config_then_default():
    assert resolve_ai_mode(SimpleNamespace(no_ai=False, ai_mode=None), _Cfg("pentest")) == "pentest"
    assert resolve_ai_mode(SimpleNamespace(no_ai=False, ai_mode=None), _Cfg()) == "analyze"


def test_targets_from_scope_exact_and_wildcard():
    cfg = {"in_scope": ["example.com", "shop.example.com", "*.api.example.com"]}
    assert targets_from_scope(cfg) == ["example.com", "shop.example.com", "api.example.com"]


def test_targets_from_scope_empty():
    assert targets_from_scope({}) == []
    assert targets_from_scope({"in_scope": []}) == []


def test_should_enumerate_auto():
    # wildcard -> enumerate
    assert should_enumerate("auto", ["*.example.com"]) is True
    assert should_enumerate("auto", ["example.com", "*.example.com"]) is True
    # exact hosts only -> no enumeration (the single-domain case)
    assert should_enumerate("auto", ["example.com"]) is False
    assert should_enumerate("auto", ["a.com", "b.com"]) is False
    # unconstrained -> enumerate under the seed
    assert should_enumerate("auto", []) is True


def test_should_enumerate_overrides():
    assert should_enumerate("always", ["example.com"]) is True   # forced on
    assert should_enumerate("never", ["*.example.com"]) is False  # forced off
