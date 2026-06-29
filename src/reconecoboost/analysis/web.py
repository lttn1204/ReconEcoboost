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

from ..core.errors import AIError
from ..core.models import Domain, ModuleResult, ModuleStatus, Stage
from ..core.module import BaseModule
from ..graph.models import Subgraph
from ..logging.setup import get_logger
from ..orchestration.registry import register
from ..prompts import PromptManager
from .agent_http import AgentHttp

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
        # Scratchpad / chain-of-thought (Vulnhuntr-style): the model reasons here
        # FIRST — which leads it examined, what it dropped as FP and why — before
        # promoting anything into `vulnerabilities`.
        "analysis": {"type": "string"},
        # Manual-pentest dossier so the human can KEEP TESTING, not just read results:
        # the stack actually in use, what to watch out for, and what to research.
        "tech_stack": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technology": {"type": "string"},
                    "version": {"type": "string"},
                    "what_to_check": {"type": "string"},
                    "search_terms": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["technology", "what_to_check", "search_terms"],
                "additionalProperties": False,
            },
        },
        # Concrete manual next steps to continue the engagement by hand.
        "manual_next_steps": {"type": "array", "items": {"type": "string"}},
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
                    "confidence_score": {"type": "number"},
                    "rationale": {"type": "string"},
                    "evidence": {"type": "string"},
                    "impact": {"type": "string"},
                    "test_steps": {"type": "array", "items": {"type": "string"}},
                    "poc": {"type": "string"},
                },
                "required": ["title", "vuln_type", "target", "severity", "confidence",
                             "confidence_score", "rationale", "evidence", "impact",
                             "test_steps", "poc"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["analysis", "tech_stack", "manual_next_steps", "vulnerabilities"],
    "additionalProperties": False,
}

# What the agentic loop asks the model for each iteration: a thought, a batch of
# concrete non-destructive probes to run, whether it is done, and fuzzing seeds to
# export (C). Headers are an array of {name,value} to stay strict-schema-friendly.
ACTION_PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "thought": {"type": "string"},
        "done": {"type": "boolean"},
        "actions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "method": {"type": "string"},
                    "url": {"type": "string"},
                    "headers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "value": {"type": "string"},
                            },
                            "required": ["name", "value"],
                            "additionalProperties": False,
                        },
                    },
                    "body": {"type": "string"},
                    "reason": {"type": "string"},
                    "expect": {"type": "string"},
                },
                "required": ["method", "url", "headers", "body", "reason", "expect"],
                "additionalProperties": False,
            },
        },
        "proposed_fuzz": {
            "type": "object",
            "properties": {
                "endpoints": {"type": "array", "items": {"type": "string"}},
                "params": {"type": "array", "items": {"type": "string"}},
                "dirwords": {"type": "array", "items": {"type": "string"}},
                "subwords": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["endpoints", "params", "dirwords", "subwords"],
            "additionalProperties": False,
        },
    },
    "required": ["thought", "done", "actions", "proposed_fuzz"],
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


def _prompt_exists(ctx, name: str) -> bool:
    """Whether the resolved prompt file for ``name`` exists for this version."""
    manager = _prompt_manager(ctx)
    return (manager.prompts_dir / "web" / f"{_prompt_name(ctx, name)}.md").exists()


def _response_bodies(ctx, max_files: int = 25, max_bytes: int = 2500) -> list[dict]:
    """Bounded sample of the raw response bodies js_fetch stored (deep evidence, A).

    Reads only the first ``max_files`` indexed files (not the whole corpus — that can
    be thousands) and truncates each, so the agent sees REAL response content without
    blowing the context or memory.
    """
    results_dir = getattr(ctx, "results_dir", None)
    if not results_dir:
        return []
    index = Path(results_dir) / "responses" / "index.json"
    if not index.exists():
        return []
    try:
        entries = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[dict] = []
    for entry in entries[:max_files]:
        url, fname = entry.get("url"), entry.get("file")
        if not url or not fname:
            continue
        path = Path(fname) if Path(fname).is_absolute() else index.parent / fname
        try:
            body = path.read_text(encoding="utf-8", errors="ignore")[:max_bytes]
        except OSError:
            continue
        out.append({"url": url, "body": body})
    return out


# Subscription/API quota or rate-limit exhaustion surfaces as an AIError whose message
# carries one of these hints. When the agentic loop hits this, it checkpoints and pauses
# instead of crashing — so a later run (with quota restored) can resume.
_QUOTA_HINTS = ("usage limit", "rate limit", "rate_limit", "quota", "limit reached",
                "too many requests", "429", "resets at", "try again later")


def _is_quota_error(exc: Exception) -> bool:
    return any(h in str(exc).lower() for h in _QUOTA_HINTS)


class _AgenticPaused(Exception):
    """Raised to pause the agentic loop (quota hit or soft AI-call cap) so it can resume."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


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
        log = get_logger("module.ai_pentest", run_id=getattr(ctx, "run_id", None))

        payload = _curated_payload(ctx)
        if not payload["nodes"]:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"nodes": 0}
            return result

        prior = ctx.repository.list_findings(ctx.run_id)
        graph_json = json.dumps(payload, sort_keys=True)
        intel_json = json.dumps(prior, sort_keys=True, default=str)
        bodies_json = json.dumps(_response_bodies(ctx), default=str)  # deep evidence (A)
        tokens: list = []

        # B+C — agentic loop: opt-in (ai.agentic.enabled / --ai-agentic) because it
        # sends LIVE, in-scope, non-destructive requests to confirm leads. Needs the v5
        # agent_plan prompt; otherwise fall back to passive analysis.
        agentic = bool(((ctx.config.ai or {}).get("agentic") or {}).get("enabled"))
        if agentic and _prompt_exists(ctx, "agent_plan"):
            return self._run_agentic(ctx, result, graph_json, intel_json,
                                     bodies_json, tokens, log)
        if agentic:
            log.warning("agentic on but no agent_plan prompt for this prompt_version "
                        "(needs v5); running passive analysis instead.")

        # Passive synthesis — deep evidence (bodies), no live probing.
        data = self._synthesize(ctx, graph_json, intel_json, bodies_json,
                                "(no live probing performed)", tokens)
        data = self._maybe_two_stage(ctx, graph_json, intel_json, data, tokens, log)
        vulns = self._persist_results(ctx, data, transcript=[], seeds={})
        result.status = ModuleStatus.SUCCESS
        result.produced = len(vulns)
        result.meta = {
            "vulnerabilities": len(vulns),
            "tokens": [t for t in tokens if t is not None],
            "two_stage": bool((ctx.config.ai or {}).get("two_stage")),
            "agentic": False, "probes": 0,
        }
        return result

    # -- agentic orchestration (B+C) -----------------------------------------
    def _run_agentic(self, ctx, result, graph_json, intel_json, bodies_json, tokens, log):
        """Resumable agentic flow: loop (probe) → synthesize → two_stage → persist.

        On a quota/usage-limit hit (or the soft AI-call cap), checkpoints to
        ``results/<run>/agentic_state.json`` and returns a PAUSED result; re-running the
        same command resumes from the checkpoint when quota is back.
        """
        counters = {"calls": 0, "iteration": 0}
        state = self._load_state(ctx) or {}
        transcript: list = list(state.get("transcript") or [])
        seeds: dict = {k: list(state.get("seeds", {}).get(k, []))
                       for k in ("endpoints", "params", "dirwords", "subwords")}
        loop_done = bool(state.get("loop_done"))
        counters["iteration"] = int(state.get("iteration") or 0)
        if state:
            log.info("resuming agentic from checkpoint: iter %d, %d probe(s), loop_done=%s",
                     counters["iteration"], len(transcript), loop_done)

        try:
            if not loop_done:
                transcript, seeds, loop_tokens = self._agentic_loop(
                    ctx, graph_json, intel_json, bodies_json, log,
                    transcript, seeds, counters)
                tokens.extend(loop_tokens)
                loop_done = True
                self._save_state(ctx, transcript=transcript, seeds=seeds,
                                 iteration=counters["iteration"], loop_done=True)
            self._export_fuzz_seeds(ctx, seeds, log)
            transcript_json = (json.dumps(transcript, default=str)
                               if transcript else "(no probes ran)")
            data = self._synthesize(ctx, graph_json, intel_json, bodies_json,
                                    transcript_json, tokens, counters)
            data = self._maybe_two_stage(ctx, graph_json, intel_json, data, tokens, log)
        except _AgenticPaused as pause:
            self._save_state(ctx, transcript=transcript, seeds=seeds,
                             iteration=counters["iteration"], loop_done=loop_done)
            # keep the probes already gathered so nothing is lost on resume
            self._persist_results(ctx, {}, transcript, seeds)
            log.warning("agentic PAUSED: %s. Checkpoint saved to %s — re-run the same "
                        "command when quota returns to resume.",
                        pause.reason, self._state_path(ctx))
            result.status = ModuleStatus.SUCCESS
            result.produced = 0
            result.meta = {"agentic": True, "paused": True, "reason": str(pause.reason),
                           "probes": len(transcript),
                           "tokens": [t for t in tokens if t is not None]}
            return result

        self._clear_state(ctx)  # finished cleanly — drop the checkpoint
        vulns = self._persist_results(ctx, data, transcript, seeds)
        result.status = ModuleStatus.SUCCESS
        result.produced = len(vulns)
        result.meta = {
            "vulnerabilities": len(vulns),
            "tokens": [t for t in tokens if t is not None],
            "two_stage": bool((ctx.config.ai or {}).get("two_stage")),
            "agentic": True, "paused": False, "probes": len(transcript),
        }
        return result

    def _agentic_loop(self, ctx, graph_json, intel_json, bodies_json, log,
                      transcript, seeds, counters):
        """Plan → probe (guarded HTTP) → observe → adapt, until done or out of budget.

        Resumable: ``transcript``/``seeds`` carry prior state, ``counters['iteration']``
        is the next round. Checkpoints after every round; raises ``_AgenticPaused`` (via
        ``_ai_call``) on quota so the caller can save and resume.
        """
        cfg = (ctx.config.ai or {}).get("agentic") or {}
        client = AgentHttp(
            ctx.scope,
            allowed_methods=cfg.get("methods"),
            max_requests=int(cfg.get("max_requests", 120)),
            rate_per_s=float(cfg.get("rate_per_s", 3)),
            timeout_s=float(cfg.get("timeout_s", 15)),
            max_body_bytes=int(cfg.get("max_body_bytes", 20000)),
            run_id=getattr(ctx, "run_id", None),
        )
        client.count = len(transcript)  # resume: prior probes count against the budget
        max_iter = int(cfg.get("max_iterations", 6))
        per_iter = int(cfg.get("per_iteration_actions", 12))
        manager = _prompt_manager(ctx)
        plan_name = _prompt_name(ctx, "agent_plan")
        seed_sets = {k: set(seeds.get(k, [])) for k in
                     ("endpoints", "params", "dirwords", "subwords")}
        tokens: list = []
        try:
            for it in range(int(counters.get("iteration", 0)), max_iter):
                plan_prompt = manager.render("web", plan_name, {
                    "graph": graph_json, "intel": intel_json, "bodies": bodies_json,
                    "targets": _targets(ctx), "budget": str(client.budget_left),
                    "transcript": (json.dumps(transcript, default=str)
                                   if transcript else "(no probes yet)"),
                })
                resp = self._ai_call(ctx, plan_prompt, ACTION_PLAN_SCHEMA, counters)
                tokens.append(resp.usage)
                plan = resp.parsed or {}
                self._merge_seeds(seed_sets, plan.get("proposed_fuzz") or {})
                actions = (plan.get("actions") or [])[:per_iter]
                log.info("agentic iter %d/%d: %d action(s), budget=%d | %s",
                         it + 1, max_iter, len(actions), client.budget_left,
                         (plan.get("thought") or "")[:120])
                for a in actions:
                    if client.budget_left <= 0:
                        break
                    headers = {h["name"]: h["value"]
                               for h in (a.get("headers") or []) if h.get("name")}
                    res = client.request(a.get("method", "GET"), a.get("url", ""),
                                         headers=headers, body=a.get("body", ""))
                    transcript.append(self._compact_step(a, res))
                counters["iteration"] = it + 1
                seeds = {k: sorted(v) for k, v in seed_sets.items()}
                self._save_state(ctx, transcript=transcript, seeds=seeds,
                                 iteration=it + 1, loop_done=False)
                if plan.get("done") or not actions or client.budget_left <= 0:
                    break
        finally:
            client.close()
        log.info("agentic loop finished: %d probe(s) executed", len(transcript))
        return transcript, {k: sorted(v) for k, v in seed_sets.items()}, tokens

    def _ai_call(self, ctx, prompt, schema, counters):
        """One AI call with a soft cap + quota detection (raises ``_AgenticPaused``)."""
        cap = int(((ctx.config.ai or {}).get("agentic") or {}).get("max_ai_calls", 0) or 0)
        if cap and counters.get("calls", 0) >= cap:
            raise _AgenticPaused(f"soft AI-call cap reached ({cap}) — pausing to spare quota")
        counters["calls"] = counters.get("calls", 0) + 1
        try:
            return ctx.ai.generate(prompt, schema=schema)
        except AIError as exc:
            if _is_quota_error(exc):
                raise _AgenticPaused(f"quota/usage limit hit: {exc}") from exc
            raise

    def _synthesize(self, ctx, graph_json, intel_json, bodies_json, transcript_json,
                    tokens, counters=None):
        """Final synthesis call → parsed findings dict. Uses ``_ai_call`` when in an
        agentic run (``counters`` given) so a quota hit pauses instead of crashing."""
        prompt = _prompt_manager(ctx).render(
            "web", _prompt_name(ctx, "pentest"),
            {"graph": graph_json, "intel": intel_json, "targets": _targets(ctx),
             "bodies": bodies_json, "transcript": transcript_json},
        )
        if counters is not None:
            response = self._ai_call(ctx, prompt, PENTEST_SCHEMA, counters)
        else:
            response = ctx.ai.generate(prompt, schema=PENTEST_SCHEMA)
        tokens.append(response.usage)
        return response.parsed or {}

    def _maybe_two_stage(self, ctx, graph_json, intel_json, data, tokens, log):
        """Optional self-critique verify pass (ai.two_stage). A quota error here is
        non-fatal — we keep the first-pass findings rather than lose them."""
        if not (bool((ctx.config.ai or {}).get("two_stage")) and data.get("vulnerabilities")):
            return data
        try:
            verified = self._verify_pass(ctx, graph_json, intel_json, data)
        except AIError as exc:
            if _is_quota_error(exc):
                log.warning("two_stage verify skipped (quota): %s", exc)
                return data
            raise
        if verified is not None:
            tokens.append(verified.pop("_usage", None))
            return verified
        return data

    def _persist_results(self, ctx, data, transcript, seeds):
        """Persist vulnerabilities + manual-pentest dossier + probe transcript."""
        vulns = data.get("vulnerabilities", [])
        for vuln in vulns:
            ctx.repository.add_finding(
                ctx.run_id, kind="vulnerability",
                title=vuln.get("title", "(untitled)"), severity=vuln.get("severity"),
                detail=vuln, source="ai_pentest")
        guide = {"analysis": data.get("analysis", ""),
                 "tech_stack": data.get("tech_stack", []),
                 "manual_next_steps": data.get("manual_next_steps", [])}
        if guide["tech_stack"] or guide["manual_next_steps"] or guide["analysis"]:
            ctx.repository.add_finding(
                ctx.run_id, kind="pentest_guide", title="AI manual-pentest guide",
                severity="info", detail=guide, source="ai_pentest")
        if transcript:
            ctx.repository.add_finding(
                ctx.run_id, kind="agent_log",
                title=f"Agentic probe transcript ({len(transcript)} request(s))",
                severity="info",
                detail={"requests": transcript, "fuzz_seeds": seeds},
                source="ai_pentest")
        return vulns

    # -- agentic checkpoint (resume across quota windows) ----------------------
    @staticmethod
    def _state_path(ctx):
        rd = getattr(ctx, "results_dir", None)
        return (Path(rd) / "agentic_state.json") if rd else None

    def _save_state(self, ctx, **fields) -> None:
        path = self._state_path(ctx)
        if path is None:
            return
        try:
            path.write_text(json.dumps(fields, default=str), encoding="utf-8")
        except OSError:
            pass

    def _load_state(self, ctx):
        path = self._state_path(ctx)
        if path is None or not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _clear_state(self, ctx) -> None:
        path = self._state_path(ctx)
        if path is not None and path.exists():
            try:
                path.unlink()
            except OSError:
                pass

    @staticmethod
    def _merge_seeds(seeds: dict, proposed: dict) -> None:
        for key in seeds:
            for word in (proposed.get(key) or []):
                word = str(word).strip()
                if word:
                    seeds[key].add(word)

    @staticmethod
    def _compact_step(action: dict, result: dict) -> dict:
        """Compact one probe (request + outcome) for the transcript / evidence."""
        step = {"method": action.get("method", "GET"), "url": action.get("url", ""),
                "reason": action.get("reason", "")}
        if result.get("refused"):
            step["result"] = f"REFUSED: {result['refused']}"
        elif result.get("error"):
            step["result"] = f"ERROR: {result['error']}"
        else:
            step["status"] = result.get("status")
            if result.get("location"):
                step["location"] = result["location"]
            snippet = (result.get("body") or "")[:800]
            if result.get("body_truncated"):
                snippet += " …[truncated]"
            step["response_snippet"] = snippet
        return step

    @staticmethod
    def _export_fuzz_seeds(ctx, seeds: dict, log) -> None:
        """C — write agent-proposed wordlists to the AI-seam files the fuzzers read.

        Merges (dedup) into ai_params/ai_dirwords/ai_subwords (consumed by arjun /
        feroxbuster / dns_resolve+permutation on a re-run) plus a new ai_endpoints.txt,
        and records a recon_note so the report surfaces them for manual fuzzing.
        """
        results_dir = getattr(ctx, "results_dir", None)
        if not results_dir or not seeds:
            return
        mapping = {"params": "ai_params.txt", "dirwords": "ai_dirwords.txt",
                   "subwords": "ai_subwords.txt", "endpoints": "ai_endpoints.txt"}
        written: dict = {}
        for key, fname in mapping.items():
            words = seeds.get(key) or []
            if not words:
                continue
            path = Path(results_dir) / fname
            existing: set = set()
            if path.exists():
                existing = {ln.strip() for ln in
                            path.read_text(encoding="utf-8").splitlines() if ln.strip()}
            merged = sorted(existing | set(words))
            path.write_text("\n".join(merged) + "\n", encoding="utf-8")
            written[fname] = len(merged)
        if written:
            log.info("agentic exported fuzz seeds: %s", written)
            ctx.repository.add_finding(
                ctx.run_id, kind="recon_note", severity="info",
                title="Agent-proposed fuzzing seeds (re-run to fuzz with these)",
                detail={"files": written, "seeds": seeds}, source="ai_pentest")

    @staticmethod
    def _verify_pass(ctx, graph_json: str, intel_json: str, first: dict) -> dict | None:
        """Second self-critique pass: re-verify candidates, drop the weak ones.

        Returns the refined parsed dict (with a transient ``_usage`` key), or
        ``None`` if the verify prompt for this prompt_version is absent (→ skip).
        """
        log = get_logger("module.ai_pentest", run_id=getattr(ctx, "run_id", None))
        manager = _prompt_manager(ctx)
        verify_name = _prompt_name(ctx, "pentest_verify")
        if not (manager.prompts_dir / "web" / f"{verify_name}.md").exists():
            log.warning("two_stage on but no pentest_verify prompt for this "
                        "prompt_version; keeping first-pass result.")
            return None
        prompt = manager.render(
            "web", verify_name,
            {
                "graph": graph_json,
                "intel": intel_json,
                "targets": _targets(ctx),
                "candidates": json.dumps(first, sort_keys=True, default=str),
            },
        )
        before = len(first.get("vulnerabilities", []))
        response = ctx.ai.generate(prompt, schema=PENTEST_SCHEMA)
        refined = response.parsed or {}
        after = len(refined.get("vulnerabilities", []))
        log.info("two_stage verify: %d candidate(s) -> %d after critique", before, after)
        refined["_usage"] = response.usage
        return refined
