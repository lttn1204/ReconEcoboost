"""Tests for deterministic triage (scorer + pipeline module)."""

import json

from reconecoboost.analysis.triage import (
    param_vuln_classes,
    path_keyword_hits,
    score_targets,
)
from reconecoboost.config.loader import Config
from reconecoboost.core.context import Context
from reconecoboost.core.models import Domain, ModuleStatus
from reconecoboost.core.scope import Scope
from reconecoboost.engine import Normalizer, ParsedRecord
from reconecoboost.modules.web.triage import Triage
from reconecoboost.persistence import Database, Store


# --- pure scorer ----------------------------------------------------------
def test_param_vuln_classes_from_gf_sets():
    assert "ssrf" in param_vuln_classes({"url"})
    assert "sqli" in param_vuln_classes({"id"})
    assert param_vuln_classes({"totally_random"}) == []


def test_path_keyword_hits():
    assert "admin" in path_keyword_hits("https://x/admin/users")
    assert path_keyword_hits("https://x/style.css") == []


def test_method_anomaly_ranks_top_and_is_never_demoted():
    urls = [
        {"key": "https://x/api/upload",
         "attributes": {"methods": {"GET": {"status": 403, "length": 0},
                                    "POST": {"status": 200, "length": 1234}}}},
        {"key": "https://x/style.css", "attributes": {"status_code": 200}},
    ]
    res = score_targets([], urls, [])
    top = res.targets[0]
    assert top["key"] == "https://x/api/upload"
    assert "method-anomaly" in top["tags"]
    assert top["score"] > 0


def test_catch_all_collapsed_but_signal_url_preserved():
    # 6 identical 200/246 paths => catch-all noise; one of them carries a param.
    urls = [{"key": f"https://x/p{i}", "attributes": {"status_code": 200, "content_length": 246}}
            for i in range(6)]
    urls.append({"key": "https://x/search?id=1",
                 "attributes": {"status_code": 200, "content_length": 246}})
    res = score_targets([], urls, [])

    assert res.collapsed and res.collapsed[0]["count"] >= 5
    by_key = {t["key"]: t for t in res.targets}
    # the param-bearing URL is NOT collapsed (protected) and outranks the noise
    assert by_key["https://x/search?id=1"]["score"] > 0
    assert "sqli" in by_key["https://x/search?id=1"]["tags"]
    assert by_key["https://x/p0"]["score"] < 0  # demoted, but still present
    assert len(res.targets) == 7               # nothing dropped


def test_nuclei_finding_boosts_host():
    hosts = [{"key": "https://x", "attributes": {}}]
    findings = [{"severity": "critical", "host": "https://x", "matched_at": "https://x"}]
    res = score_targets(hosts, [], findings)
    assert res.targets[0]["key"] == "https://x"
    assert "nuclei:critical" in res.targets[0]["tags"]
    assert res.targets[0]["score"] >= 100


# --- pipeline module ------------------------------------------------------
def test_triage_module_writes_results_and_finding(tmp_path):
    db = Database(":memory:")
    db.connect()
    db.initialize()
    store = Store(db)
    ctx = Context(
        domain=Domain.WEB, scope=Scope(targets=["example.com"]),
        config=Config(), repository=store, results_dir=tmp_path,
    )
    store.start_run(ctx)
    store.persist_normalization(ctx.run_id, Normalizer().normalize([
        ParsedRecord("host", "https://a.example.com", tool="httpx"),
        ParsedRecord("url", "https://a.example.com/admin?id=1",
                     attributes={"status_code": 200}, tool="httpx"),
        ParsedRecord("url", "https://a.example.com/style.css",
                     attributes={"status_code": 200}, tool="katana"),
    ]))

    result = Triage().run(ctx)

    assert result.status == ModuleStatus.SUCCESS
    # results files written for the user to track
    data = json.loads((tmp_path / "triage.json").read_text())
    assert data["stats"]["scored"] == 3
    assert (tmp_path / "triage.txt").read_text().startswith("ReconEcoboost")
    # a single triage finding persisted, with the admin?id URL ranked first
    triage_finding = next(f for f in store.list_findings(ctx.run_id) if f["kind"] == "triage")
    detail = json.loads(triage_finding["detail_json"])
    assert detail["top"][0]["key"] == "https://a.example.com/admin?id=1"
    assert "sqli" in detail["top"][0]["tags"]
    store.close()
