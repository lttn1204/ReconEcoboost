"""Web analysis modules — AI recon intelligence and AI pentest.

Two AI tasks at the reasoning end of the "AI reasons, Engine executes" boundary
(architecture doc 10/11/12). Both consume a curated subgraph (never raw output),
render an external prompt, ask the provider for *structured* output, and persist
results as ``finding`` records.

  ai_recon_intel  — compile recon intelligence (tech, interesting endpoints,
                    sensitive cases) for a human pentester's manual analysis.
  ai_pentest      — use the recon + intel to hunt concrete, testable vulns.

Which of these run is controlled by the AI mode (off | analyze | pentest),
resolved in the CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from ..core.models import Domain, ModuleResult, ModuleStatus, Stage
from ..core.module import BaseModule
from ..graph.models import Subgraph
from ..orchestration.registry import register
from ..prompts import PromptManager

RECON_INTEL_SCHEMA = {
    "type": "object",
    "properties": {
        "technologies": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "version": {"type": "string"},
                    "category": {"type": "string"},
                    "note": {"type": "string"},
                },
                "required": ["name", "note"],
                "additionalProperties": False,
            },
        },
        "interesting_endpoints": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["url", "reason"],
                "additionalProperties": False,
            },
        },
        "sensitive_findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "detail": {"type": "string"},
                    "where": {"type": "string"},
                    "severity": {"type": "string"},
                },
                "required": ["title", "detail", "severity"],
                "additionalProperties": False,
            },
        },
        "notes": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["technologies", "interesting_endpoints", "sensitive_findings", "notes"],
    "additionalProperties": False,
}

PENTEST_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "vuln_type": {"type": "string"},
                    "target": {"type": "string"},
                    "severity": {"type": "string"},
                    "confidence": {"type": "string"},
                    "rationale": {"type": "string"},
                    "evidence": {"type": "string"},
                    "test_steps": {"type": "array", "items": {"type": "string"}},
                    "poc": {"type": "string"},
                },
                "required": ["title", "vuln_type", "target", "severity", "confidence",
                             "rationale", "evidence", "test_steps", "poc"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["vulnerabilities"],
    "additionalProperties": False,
}


def _prompt_manager(ctx) -> PromptManager:
    prompts_dir = (ctx.config.ai.get("prompts", {}) or {}).get("dir", "prompts")
    return PromptManager(Path(prompts_dir))


def _prompt_name(ctx, name: str) -> str:
    """Resolve a prompt name to the configured version (ai.prompt_version).

    v1/default → ``recon_intel`` (prompts/web/recon_intel.md);
    any other version → ``<version>/recon_intel`` (prompts/web/<version>/...).
    Lets multiple prompt sets coexist and be A/B-selected via config.
    """
    version = str((ctx.config.ai or {}).get("prompt_version", "v1")).strip().lower()
    if version in ("", "v1", "default"):
        return name
    return f"{version}/{name}"


def _graph_payload(ctx) -> dict:
    nodes = {n.id: n for n in ctx.graph.nodes(ctx.run_id)}
    edges = ctx.graph.edges(ctx.run_id)
    return Subgraph(nodes=nodes, edges=edges).to_prompt_dict()


def _triage_detail(ctx) -> dict | None:
    """The persisted deterministic-triage ranking, if the triage stage ran."""
    for finding in ctx.repository.list_findings(ctx.run_id):
        if finding.get("kind") == "triage" and finding.get("detail_json"):
            try:
                return json.loads(finding["detail_json"])
            except (json.JSONDecodeError, TypeError):
                return None
    return None


def _host_of(key: str) -> str:
    """The origin (scheme://netloc) a URL belongs to; a host key maps to itself."""
    parts = urlsplit(key)
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return key


def _select_keys(cfg: dict, triage: dict, host_keys: list[str]) -> list[str]:
    """Ordered, priority-ranked keys to seed the curated context.

    Priority (earliest survives the max_nodes cap):
      1. guaranteed method/param/anomaly leads (every host)
      2. scope-specific picks:
         - global   : the top-N ranked targets across all hosts
         - per_host : (optionally) every live host root, then each subdomain's
                      top-K URLs, round-robined for fair coverage
    """
    top = triage.get("top", []) or []
    wanted: list[str] = []

    def add(k: str) -> None:
        if k and k not in wanted:
            wanted.append(k)

    for key in triage.get("must_include", []) or []:   # 1. always-in leads
        add(key)

    scope = str(cfg.get("context_scope", "global")).lower()
    if scope == "per_host":
        if bool(cfg.get("context_include_host_roots", True)):
            for hk in host_keys:                        # every live subdomain root
                add(hk)
        per_host = int(cfg.get("context_per_host", 5) or 5)
        by_host: dict[str, list[str]] = {}
        for item in top:                                # urls grouped by host, score order
            if item.get("kind") == "host":
                continue
            by_host.setdefault(_host_of(item["key"]), []).append(item["key"])
        for i in range(per_host):                       # round-robin for fairness
            for urls in by_host.values():
                if i < len(urls):
                    add(urls[i])
    else:  # global
        top_n = int(cfg.get("context_top_n", 25) or 25)
        for item in top[:top_n]:
            add(item["key"])
    return wanted


def _curated_payload(ctx) -> dict:
    """Compact, pre-ranked context for the AI stages.

    Instead of dumping the whole graph, send only the triage shortlist plus their
    1-hop neighbors, annotated with the deterministic triage score/tags/reasons.
    Two scopes (config ``ai.context_scope``): ``global`` (top-N across all hosts)
    or ``per_host`` (each subdomain represented). ``ai.context_max_nodes`` is the
    hard ceiling either way.

    Falls back to the full graph when ``ai.context: full``, or when no triage
    ranking exists (e.g. ``--run-id`` on an older run).
    """
    cfg = ctx.config.ai or {}
    if str(cfg.get("context", "curated")).lower() == "full":
        return _graph_payload(ctx)
    triage = _triage_detail(ctx)
    if not triage:
        return _graph_payload(ctx)  # full-graph fallback

    max_nodes = int(cfg.get("context_max_nodes", 60) or 60)
    top = triage.get("top", []) or []

    all_nodes = {n.id: n for n in ctx.graph.nodes(ctx.run_id)}
    all_edges = ctx.graph.edges(ctx.run_id)
    if not all_nodes:
        return {"nodes": [], "edges": []}

    key_to_id: dict[str, int] = {}
    for nid, node in all_nodes.items():
        key_to_id.setdefault(node.key, nid)

    host_keys = [n.key for n in all_nodes.values() if n.asset_type == "host"]
    wanted = _select_keys(cfg, triage, host_keys)

    adj = Subgraph(nodes=all_nodes, edges=all_edges).adjacency(directed=False)
    seed_ids = [key_to_id[k] for k in wanted if k in key_to_id]
    chosen: list[int] = list(dict.fromkeys(seed_ids))   # ordered, unique, seeds first
    # Add only *context* neighbors (the containing host, technologies) — never
    # auto-expand a host into all its URLs, so context_top_n / per_host actually
    # govern which URLs are included.
    context_types = {"host", "technology", "subdomain"}
    for nid in seed_ids:
        for _edge, neighbor in adj.get(nid, []):
            if neighbor not in chosen and all_nodes[neighbor].asset_type in context_types:
                chosen.append(neighbor)
    chosen = chosen[:max_nodes]                          # cap (seeds kept first)
    chosen_set = set(chosen)

    sub = Subgraph(
        nodes={nid: all_nodes[nid] for nid in chosen_set},
        edges=[e for e in all_edges if e.src_id in chosen_set and e.dst_id in chosen_set],
    )
    payload = sub.to_prompt_dict()

    # annotate nodes with the deterministic triage signal (free leads for the AI)
    info_by_key = {t["key"]: t for t in top}
    for node in payload["nodes"]:
        info = info_by_key.get(node["key"])
        if info:
            node["attributes"] = {
                **(node["attributes"] or {}),
                "_triage": {"score": info.get("score"), "tags": info.get("tags"),
                            "reasons": info.get("reasons")},
            }
    return payload


def _targets(ctx) -> str:
    return ", ".join(ctx.scope.targets) or "(unspecified)"


def _require_ai(ctx) -> None:
    if ctx.ai is None or ctx.graph is None or ctx.repository is None:
        raise NotImplementedError("AI provider / graph / store not available on context")


@register
class AiReconIntel(BaseModule):
    """Compile recon intelligence for manual analysis (AI mode: analyze | pentest)."""

    name = "ai_recon_intel"
    domain = Domain.WEB
    stage = Stage.ANALYSIS
    requires = ("normalized",)
    produces = ("intel",)
    tool = None
    parser = None
    run_once = True   # analysis — runs once after the discovery loop

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        _require_ai(ctx)

        payload = _curated_payload(ctx)
        if not payload["nodes"]:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"nodes": 0}
            return result

        prompt = _prompt_manager(ctx).render(
            "web", _prompt_name(ctx, "recon_intel"),
            {"graph": json.dumps(payload, sort_keys=True), "targets": _targets(ctx)},
        )
        response = ctx.ai.generate(prompt, schema=RECON_INTEL_SCHEMA)
        data = response.parsed or {}

        produced = 0
        # One consolidated intel finding (tech + endpoints + notes)...
        ctx.repository.add_finding(
            ctx.run_id,
            kind="recon_intel",
            title="Technology & recon intelligence",
            severity="info",
            detail={
                "technologies": data.get("technologies", []),
                "interesting_endpoints": data.get("interesting_endpoints", []),
                "notes": data.get("notes", []),
            },
            source="ai_recon_intel",
        )
        produced += 1
        # ...plus each sensitive case as its own finding for triage.
        for item in data.get("sensitive_findings", []):
            ctx.repository.add_finding(
                ctx.run_id,
                kind="recon_intel",
                title=item.get("title", "(untitled)"),
                severity=item.get("severity"),
                detail=item,
                source="ai_recon_intel",
            )
            produced += 1

        result.status = ModuleStatus.SUCCESS
        result.produced = produced
        result.meta = {"nodes": len(payload["nodes"]), "tokens": response.usage}
        return result


@register
class AiPentest(BaseModule):
    """AI-driven vulnerability hunting using recon + intel (AI mode: pentest)."""

    name = "ai_pentest"
    domain = Domain.WEB
    stage = Stage.ANALYSIS
    requires = ("intel",)
    produces = ("vulnerability",)
    tool = None
    parser = None
    run_once = True   # analysis — runs once after the discovery loop

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        _require_ai(ctx)

        payload = _curated_payload(ctx)
        if not payload["nodes"]:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"nodes": 0}
            return result

        prior = ctx.repository.list_findings(ctx.run_id)
        prompt = _prompt_manager(ctx).render(
            "web", _prompt_name(ctx, "pentest"),
            {
                "graph": json.dumps(payload, sort_keys=True),
                "intel": json.dumps(prior, sort_keys=True, default=str),
                "targets": _targets(ctx),
            },
        )
        response = ctx.ai.generate(prompt, schema=PENTEST_SCHEMA)
        data = response.parsed or {}

        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            ctx.repository.add_finding(
                ctx.run_id,
                kind="vulnerability",
                title=vuln.get("title", "(untitled)"),
                severity=vuln.get("severity"),
                detail=vuln,
                source="ai_pentest",
            )

        result.status = ModuleStatus.SUCCESS
        result.produced = len(vulns)
        result.meta = {"vulnerabilities": len(vulns), "tokens": response.usage}
        return result
