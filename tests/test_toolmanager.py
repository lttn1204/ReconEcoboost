"""Tests for ToolManager binary discovery and validation."""

import sys
from pathlib import Path

import pytest

from reconecoboost.core.errors import ToolNotFoundError
from reconecoboost.engine import CommandExecutor, ToolManager


def _config_with_python():
    # Point a logical tool name at the running interpreter via an explicit path.
    return {"tools": {"py": {"path": sys.executable}}}


def test_resolve_explicit_path():
    tm = ToolManager(_config_with_python())
    handle = tm.resolve("py")
    assert handle.path == sys.executable
    assert handle.argv("-c", "pass") == [sys.executable, "-c", "pass"]


def test_resolve_missing_raises():
    tm = ToolManager({"tools": {}})
    with pytest.raises(ToolNotFoundError):
        tm.resolve("nope-not-here-xyz")


def test_is_available():
    tm = ToolManager(_config_with_python())
    assert tm.is_available("py")
    assert not tm.is_available("nope-not-here-xyz")


def test_preflight_non_strict_reports_missing():
    tm = ToolManager(_config_with_python())
    report = tm.preflight(["py", "nope-xyz"], strict=False)
    assert report["py"] is not None
    assert report["nope-xyz"] is None


def test_preflight_strict_raises():
    tm = ToolManager(_config_with_python())
    with pytest.raises(ToolNotFoundError):
        tm.preflight(["py", "nope-xyz"], strict=True)


def test_deshadowed_which_skips_venv_bin(monkeypatch):
    import reconecoboost.engine.toolmanager as tm
    monkeypatch.setattr(tm.sys, "prefix", "/venv")          # pretend we're in a venv
    monkeypatch.setattr(tm.sys, "base_prefix", "/usr")
    monkeypatch.setenv("PATH", "/venv/bin:/home/u/go/bin")

    def fake_which(b, path=None):
        if path is None:
            return "/venv/bin/httpx"  # default PATH search hits the venv shim
        return "/home/u/go/bin/httpx" if "/home/u/go/bin" in path else None

    monkeypatch.setattr(tm.shutil, "which", fake_which)
    assert tm.deshadowed_which("httpx") == "/home/u/go/bin/httpx"


def test_deshadowed_which_noop_outside_venv(monkeypatch):
    import reconecoboost.engine.toolmanager as tm
    monkeypatch.setattr(tm.sys, "prefix", "/usr")
    monkeypatch.setattr(tm.sys, "base_prefix", "/usr")  # not a venv
    monkeypatch.setattr(tm.shutil, "which", lambda b, path=None: "/usr/bin/whatweb")
    assert tm.deshadowed_which("whatweb") == "/usr/bin/whatweb"


def test_deshadowed_which_keeps_nonvenv_candidate(monkeypatch):
    import reconecoboost.engine.toolmanager as tm
    monkeypatch.setattr(tm.sys, "prefix", "/venv")
    monkeypatch.setattr(tm.sys, "base_prefix", "/usr")
    # already resolves outside the venv bin -> left alone
    monkeypatch.setattr(tm.shutil, "which", lambda b, path=None: "/usr/bin/whatweb")
    assert tm.deshadowed_which("whatweb") == "/usr/bin/whatweb"


def test_version_best_effort():
    config = {
        "tools": {
            "py": {
                "path": sys.executable,
                "version_args": ["--version"],
                "version_pattern": r"(\d+\.\d+\.\d+)",
            }
        }
    }
    tm = ToolManager(config, executor=CommandExecutor())
    version = tm.version("py")
    assert version is not None
    assert version.split(".")[0] == str(sys.version_info.major)
