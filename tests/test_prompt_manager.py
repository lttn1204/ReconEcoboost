"""Tests for the PromptManager (front-matter parsing + rendering)."""

import pytest

from reconecoboost.core.errors import PromptError
from reconecoboost.prompts import PromptManager


def _write(tmp_path, body):
    domain_dir = tmp_path / "web"
    domain_dir.mkdir()
    (domain_dir / "t.md").write_text(body, encoding="utf-8")
    return PromptManager(tmp_path)


def test_renders_variables(tmp_path):
    pm = _write(tmp_path, "Hello {{ name }}, scope is {{ targets }}.")
    out = pm.render("web", "t", {"name": "world", "targets": "example.com"})
    assert out == "Hello world, scope is example.com."


def test_front_matter_parsed_and_stripped(tmp_path):
    pm = _write(tmp_path, "---\nname: t\nversion: 2\n---\nBody {{ x }}")
    prompt = pm.get("web", "t")
    assert prompt.meta["version"] == 2
    assert prompt.body == "Body {{ x }}"
    assert prompt.render({"x": "ok"}) == "Body ok"


def test_unknown_variable_raises(tmp_path):
    pm = _write(tmp_path, "{{ missing }}")
    with pytest.raises(PromptError):
        pm.render("web", "t", {})


def test_missing_prompt_raises(tmp_path):
    pm = PromptManager(tmp_path)
    with pytest.raises(PromptError):
        pm.get("web", "nope")


def test_json_braces_in_body_untouched(tmp_path):
    pm = _write(tmp_path, 'Schema: {"type": "object"} value {{ v }}')
    out = pm.render("web", "t", {"v": "1"})
    assert '{"type": "object"}' in out
    assert out.endswith("value 1")


def test_real_prompts_load_and_render():
    # The shipped templates should parse and render with the expected variables.
    pm = PromptManager("prompts")
    intel = pm.render("web", "recon_intel", {"graph": "{}", "targets": "example.com"})
    assert "example.com" in intel
    pentest = pm.render(
        "web", "pentest", {"graph": "{}", "intel": "[]", "targets": "example.com"}
    )
    assert "example.com" in pentest
