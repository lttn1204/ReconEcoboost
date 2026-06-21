"""Tests for selectable prompt versions (ai.prompt_version)."""

import json
from pathlib import Path

from reconecoboost.analysis.web import _prompt_name
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain
from reconecoboost.core.scope import Scope
from reconecoboost.prompts import PromptManager


def _ctx(ai_cfg):
    return Context(domain=Domain.WEB, scope=Scope(targets=["example.com"]), config=Config(ai=ai_cfg))


def test_prompt_name_resolution():
    assert _prompt_name(_ctx({}), "pentest") == "pentest"                 # default
    assert _prompt_name(_ctx({"prompt_version": "v1"}), "pentest") == "pentest"
    assert _prompt_name(_ctx({"prompt_version": "v2"}), "pentest") == "v2/pentest"
    assert _prompt_name(_ctx({"prompt_version": "V2"}), "recon_intel") == "v2/recon_intel"


def test_both_prompt_versions_render():
    pm = PromptManager(Path("prompts"))
    ctx_vars_intel = {"graph": json.dumps({"nodes": [], "edges": []}), "targets": "example.com"}
    ctx_vars_pentest = {**ctx_vars_intel, "intel": "[]"}
    for name in ("recon_intel", "v2/recon_intel"):
        out = pm.render("web", name, ctx_vars_intel)
        assert "example.com" in out and "{{" not in out
    for name in ("pentest", "v2/pentest"):
        out = pm.render("web", name, ctx_vars_pentest)
        assert "example.com" in out and "{{" not in out


def test_v2_prompts_have_expected_improvements():
    body = Path("prompts/web/v2/pentest.md").read_text(encoding="utf-8")
    assert "confidence" in body.lower()           # rubric
    assert "attacker-controlled" in body.lower()  # anti prompt-injection
    assert "_triage" in body                       # uses triage tags
    assert "example" in body.lower()               # few-shot
