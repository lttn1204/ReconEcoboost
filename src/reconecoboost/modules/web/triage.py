"""Deterministic triage stage — rank assets by signal (no LLM, zero tokens).

Reads hosts/urls + nuclei findings from the store, scores them with
``analysis.triage``, writes ``results/<run_id>/triage.{json,txt}`` so the run is
trackable, and persists a single ``triage`` finding so the report (and, later,
the AI's curated context) can use the ranking. Nothing is deleted — noise is
only demoted/grouped (see analysis.triage for the rationale).

Runs in the ANALYSIS stage after normalization + nuclei (so it sees URL statuses
and verified findings) and before the AI stages.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...analysis.triage import GUARANTEED_TAGS, render_text, score_targets
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...core.module import BaseModule
from ...logging.setup import get_logger
from ...orchestration.registry import register


def _attrs(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


@register
class Triage(BaseModule):
    name = "triage"
    domain = Domain.WEB
    stage = Stage.ANALYSIS
    # after collection (host/url), nuclei (finding) and normalization (normalized)
    requires = ("host", "url", "finding", "normalized")
    produces = ("triage",)
    run_once = True   # ranking over final assets — once after the discovery loop
    tool = None
    parser = None

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        if ctx.repository is None:
            raise NotImplementedError("persistence not available on context")
        repo = ctx.repository

        hosts = [{"key": a["canonical_key"], "attributes": _attrs(a.get("attributes_json"))}
                 for a in repo.list_assets(ctx.run_id, "host")]
        urls = [{"key": a["canonical_key"], "attributes": _attrs(a.get("attributes_json"))}
                for a in repo.list_assets(ctx.run_id, "url")]
        findings, secrets = [], []
        for f in repo.list_findings(ctx.run_id):
            detail = _attrs(f.get("detail_json"))
            if f.get("kind") == "vulnerability":
                findings.append({
                    "severity": f.get("severity"),
                    "host": detail.get("host"),
                    "matched_at": detail.get("matched_at"),
                })
            elif f.get("kind") == "secret":
                secrets.append({"url": detail.get("url"), "rule": detail.get("rule")})

        cfg = self._cfg(ctx)
        top_n = int(cfg.get("top_n", 25) or 25)
        res = score_targets(
            hosts, urls, findings,
            secrets=secrets,
            weights=cfg.get("weights"),
            cluster_threshold=int(cfg.get("cluster_threshold", 5)),
        )

        self._write_results(ctx, res, top_n)

        # one persisted finding holds the ranking (report + curated AI context)
        top = [t for t in res.targets if t["score"] > 0][:top_n]
        # assets the AI context must always include, even past top_n (method/param signal)
        must_include = [
            t["key"] for t in res.targets if set(t.get("tags", [])) & GUARANTEED_TAGS
        ]
        repo.add_finding(
            ctx.run_id,
            kind="triage",
            title="Top targets (deterministic triage)",
            severity="info",
            detail={"top": top, "must_include": must_include,
                    "collapsed": res.collapsed, "stats": res.stats},
            source="triage",
        )

        get_logger("module.triage", run_id=ctx.run_id).info(
            "triage: %d assets scored, %d high-signal, %d noise cluster(s)",
            res.stats["scored"], res.stats["high_signal"], res.stats["collapsed_clusters"],
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = len(top)
        result.meta = res.stats
        return result

    @staticmethod
    def _cfg(ctx) -> dict:
        return (ctx.config.pipeline.get("triage", {}) or {})

    @staticmethod
    def _write_results(ctx, res, top_n: int) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        out = Path(results_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "triage.json").write_text(
            json.dumps(
                {"targets": res.targets, "collapsed": res.collapsed, "stats": res.stats},
                indent=2, default=str,
            ),
            encoding="utf-8",
        )
        (out / "triage.txt").write_text(render_text(res, top_n), encoding="utf-8")
