"""Tests for the output layer (report builder + writers + manager)."""

import json
from datetime import datetime, timezone

from reconecoboost.core.entities import Relation
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.graph import SqliteKnowledgeGraph
from reconecoboost.output import OutputManager, build_report
from reconecoboost.output.writers import (
    HtmlReportWriter,
    JsonReportWriter,
    MarkdownReportWriter,
)
from reconecoboost.persistence import Database, Store


class _Scope:
    targets = ["example.com"]
    in_scope: list = []
    out_of_scope: list = []


class _Domain:
    value = "web"


class _Config:
    raw = {}


class _Ctx:
    run_id = "outrun0001"
    domain = _Domain()
    profile = "default"
    scope = _Scope()
    config = _Config()
    created_at = datetime(2026, 6, 16, tzinfo=timezone.utc)


def _seed():
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    store.start_run(_Ctx())

    records = [
        ParsedRecord("host", "https://a.example.com", attributes={"status_code": 200}, tool="httpx"),
        ParsedRecord(
            "url", "https://a.example.com/login", tool="katana",
            relations=[Relation("url", "https://a.example.com/login", "belongs_to", "host", "https://a.example.com")],
        ),
    ]
    store.persist_normalization(_Ctx.run_id, Normalizer().normalize(records))
    store.record_tool_run(
        _Ctx.run_id, tool="httpx", module="alive_detection",
        argv_redacted="httpx -json", exit_code=0, status="success", duration_s=0.5,
    )
    store.add_finding(
        _Ctx.run_id, kind="attack_plan", title="Test login", severity="high",
        detail={"rationale": "exposed", "steps": ["s1"], "targets": ["https://a.example.com/login"]},
        source="ai_attack_planning",
    )
    return store, SqliteKnowledgeGraph(db)


def test_build_report_structure():
    store, graph = _seed()
    report = build_report(store, graph, _Ctx.run_id)

    assert report["run"]["domain"] == "web"
    assert report["targets"] == ["example.com"]
    assert report["asset_counts"]["host"] == 1
    assert report["asset_counts"]["url"] == 1
    assert report["relation_count"] == 1
    assert report["finding_count"] == 1
    assert report["findings"]["attack_plan"][0]["title"] == "Test login"
    assert len(report["tool_runs"]) == 1
    store.close()


def test_json_writer_roundtrips():
    store, graph = _seed()
    report = build_report(store, graph, _Ctx.run_id)
    rendered = JsonReportWriter().render(report)
    parsed = json.loads(rendered)
    assert parsed["finding_count"] == 1
    store.close()


def test_markdown_writer_contains_sections():
    store, graph = _seed()
    report = build_report(store, graph, _Ctx.run_id)
    md = MarkdownReportWriter().render(report)
    assert "# ReconEcoboost Report" in md
    assert "## Findings" in md
    assert "Test login" in md
    assert "[HIGH]" in md
    assert "https://a.example.com/login" in md
    store.close()


def test_html_writer_wraps_content():
    store, graph = _seed()
    report = build_report(store, graph, _Ctx.run_id)
    out = HtmlReportWriter().render(report)
    assert out.startswith("<!doctype html>")
    assert "ReconEcoboost Report" in out
    store.close()


def test_manager_writes_all_formats(tmp_path):
    store, graph = _seed()
    outputs = OutputManager(tmp_path).generate(store, graph, _Ctx.run_id)
    assert set(outputs) == {"json", "markdown", "html"}
    for fmt, path in outputs.items():
        assert path.exists()
        assert path.read_text()
    # JSON file is valid JSON
    assert json.loads(outputs["json"].read_text())["run"]["id"] == _Ctx.run_id
    store.close()
