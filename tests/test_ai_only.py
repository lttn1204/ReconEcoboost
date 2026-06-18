"""Tests for AI-only-on-existing-run (--run-id) and finding dedup."""

import logging
from pathlib import Path

from reconecoboost.cli.main import _run_ai_only
from reconecoboost.config.loader import Config
from reconecoboost.core.entities import Relation
from reconecoboost.core.models import Domain
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.persistence import Store

# absolute path to the shipped prompts (test may chdir elsewhere) + offline stub
_PROMPTS = str(Path(__file__).resolve().parent.parent / "prompts")
_CONFIG = Config(ai={"provider": "stub", "prompts": {"dir": _PROMPTS}})
_LOG = logging.getLogger("test.ai_only")


class _Ctx:
    run_id = "existingrun01"
    profile = "default"

    class domain:
        value = "web"

    class scope:
        targets = ["example.com"]
        in_scope: list = []
        out_of_scope: list = []

    class config:
        raw = {}

    from datetime import datetime, timezone
    created_at = datetime(2026, 6, 17, tzinfo=timezone.utc)


def _seed_run(tmp_path):
    """Create a completed run on disk (recon data, no AI findings yet)."""
    run_dir = tmp_path / "runs" / _Ctx.run_id
    run_dir.mkdir(parents=True)
    store = Store.open(run_dir / "recon.db")
    store.start_run(_Ctx())
    records = [
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
        ParsedRecord(
            "url", "https://a.example.com/login", tool="katana",
            relations=[Relation("url", "https://a.example.com/login", "belongs_to", "host", "https://a.example.com")],
        ),
    ]
    store.persist_normalization(_Ctx.run_id, Normalizer().normalize(records))
    store.close()


class _Args:
    run_id = _Ctx.run_id
    no_ai = False
    ai_mode = "analyze"


def test_ai_only_runs_analysis_on_existing_run(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)              # so Path("runs")/run_id resolves here
    _seed_run(tmp_path)

    rc = _run_ai_only(_Args(), _CONFIG, Domain.WEB, _LOG)
    assert rc == 0

    # findings were written into the EXISTING run db (no new run dir created)
    store = Store.open(tmp_path / "runs" / _Ctx.run_id / "recon.db")
    intel = [f for f in store.list_findings(_Ctx.run_id) if f["kind"] == "recon_intel"]
    assert intel, "ai_recon_intel should have produced at least one finding"
    # reports regenerated in the same run dir
    assert (tmp_path / "runs" / _Ctx.run_id / "report.md").exists()
    store.close()


def test_reanalysis_replaces_not_duplicates(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _seed_run(tmp_path)

    _run_ai_only(_Args(), _CONFIG, Domain.WEB, _LOG)
    store = Store.open(tmp_path / "runs" / _Ctx.run_id / "recon.db")
    first = len([f for f in store.list_findings(_Ctx.run_id) if f["source"] == "ai_recon_intel"])
    store.close()

    _run_ai_only(_Args(), _CONFIG, Domain.WEB, _LOG)  # run again
    store = Store.open(tmp_path / "runs" / _Ctx.run_id / "recon.db")
    second = len([f for f in store.list_findings(_Ctx.run_id) if f["source"] == "ai_recon_intel"])
    store.close()

    assert first == second  # cleared + re-added, not piled up


def test_missing_run_returns_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    class A:
        run_id = "does-not-exist"
        no_ai = False
        ai_mode = "analyze"

    assert _run_ai_only(A(), _CONFIG, Domain.WEB, _LOG) == 2
