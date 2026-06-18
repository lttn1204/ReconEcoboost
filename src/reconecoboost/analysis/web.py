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
                    "test_steps": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["title", "vuln_type", "target", "severity", "confidence",
                             "rationale", "test_steps"],
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


def _graph_payload(ctx) -> dict:
    nodes = {n.id: n for n in ctx.graph.nodes(ctx.run_id)}
    edges = ctx.graph.edges(ctx.run_id)
    return Subgraph(nodes=nodes, edges=edges).to_prompt_dict()


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

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        _require_ai(ctx)

        payload = _graph_payload(ctx)
        if not payload["nodes"]:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"nodes": 0}
            return result

        prompt = _prompt_manager(ctx).render(
            "web", "recon_intel",
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

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        _require_ai(ctx)

        payload = _graph_payload(ctx)
        if not payload["nodes"]:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"nodes": 0}
            return result

        prior = ctx.repository.list_findings(ctx.run_id)
        prompt = _prompt_manager(ctx).render(
            "web", "pentest",
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
