"""Command-line entry point.

Wires the skeleton together: load config, configure logging, build the Context
and the resolved Pipeline. By default it only *plans* (prints the resolved DAG
order) because the modules are stubs. ``--run`` invokes the pipeline, which will
record every stage as SKIPPED until recon logic exists.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from ..config.loader import Config, ConfigLoader
from ..core.context import Context
from ..core.models import Domain
from ..core.scope import Scope
from ..ai import build_provider
from ..engine import CommandExecutor, RetryPolicy, ToolManager
from ..graph import SqliteKnowledgeGraph
from ..logging.setup import configure_logging, get_logger
from ..modules import load_domain
from ..output import OutputManager
from ..orchestration.pipeline import Pipeline
from ..orchestration.registry import REGISTRY
from ..persistence import Store


#: Discovery stages dropped when subdomain enumeration is off.
ENUMERATION_STAGES = ("asset_discovery", "vhost_discovery")

#: All AI analysis stages.
#: Generative wordlist AI (feed the deterministic brute stages) — run whenever AI
#: is on. Distinct from the end-of-run analysis AI (recon_intel/pentest).
AI_WORDLIST_STAGES = ("ai_subwords", "ai_dirwords", "ai_params")
ALL_AI_STAGES = ("ai_recon_intel", "ai_pentest", *AI_WORDLIST_STAGES)

#: Which AI stages run in each mode.
#   off      no AI at all
#   assist   ONLY the generative wordlists (AI helps recon brute stages, no post-analysis)
#   analyze  wordlists + recon-intel briefing
#   pentest  wordlists + recon-intel + AI vuln hunting
AI_STAGES_BY_MODE = {
    "off": (),
    "assist": AI_WORDLIST_STAGES,
    "analyze": ("ai_recon_intel", *AI_WORDLIST_STAGES),
    "pentest": ("ai_recon_intel", "ai_pentest", *AI_WORDLIST_STAGES),
}


def should_enumerate(mode: str, in_scope: list[str]) -> bool:
    """Decide whether to run subdomain enumeration (subfinder).

    auto:    enumerate only if scope uses a wildcard (`*.domain`); an explicit
             list of exact hosts means "just these — no enumeration"; an empty
             scope (unconstrained) enumerates under the seed.
    always:  always enumerate.   never: never enumerate.
    """
    if mode == "always":
        return True
    if mode == "never":
        return False
    entries = in_scope or []
    if any("*" in str(p) for p in entries):
        return True
    if entries:  # explicit exact hosts only
        return False
    return True  # unconstrained


def targets_from_scope(scope_cfg) -> list[str]:
    """Derive seed targets from scope.in_scope when none are passed on the CLI.

    A wildcard like ``*.example.com`` seeds the parent domain ``example.com``
    (so subfinder enumerates it); exact entries are used as-is. Order preserved,
    deduped.
    """
    seeds: list[str] = []
    for pattern in (scope_cfg.get("in_scope") or []):
        host = str(pattern).strip()
        if host.startswith("*."):
            host = host[2:]
        if host and host not in seeds:
            seeds.append(host)
    return seeds


def resolve_ai_mode(args, config) -> str:
    """Resolve the AI mode: --no-ai > --ai-mode > config ai.mode > 'analyze'."""
    if getattr(args, "no_ai", False):
        return "off"
    if getattr(args, "ai_mode", None):
        return args.ai_mode
    return (config.ai.get("mode") or "analyze").lower()


def _select_stages(profile_stages, all_names, ai_mode):
    """Resolve the enabled stage list, keeping only the AI stages allowed by mode."""
    allowed = set(AI_STAGES_BY_MODE.get(ai_mode, AI_STAGES_BY_MODE["analyze"]))
    stages = list(profile_stages) if profile_stages is not None else list(all_names)
    return [s for s in stages if s not in ALL_AI_STAGES or s in allowed]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reconecoboost",
        description="AI-assisted reconnaissance framework (skeleton).",
    )
    parser.add_argument(
        "target",
        nargs="*",
        help="Seed target(s), e.g. 'a.com.vn elearning.a.com.vn'. Each is scanned "
        "directly; combine with scope.yaml to restrict what else gets touched.",
    )
    parser.add_argument(
        "--domain",
        default=Domain.WEB.value,
        choices=[d.value for d in Domain],
        help="Recon domain (default: web).",
    )
    parser.add_argument(
        "--profile", default="default", help="Pipeline profile from pipeline.yaml."
    )
    parser.add_argument(
        "--config-dir",
        default="config",
        help="Directory containing the YAML config files.",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Execute the pipeline (stubs report SKIPPED). Default is plan-only.",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Check that the tools used by the resolved pipeline are available.",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip all AI stages (recon only). Shorthand for --ai-mode off.",
    )
    parser.add_argument(
        "--ai-mode",
        choices=["off", "assist", "analyze", "pentest"],
        default=None,
        help="off: tools only · assist: + AI wordlists only (no post-analysis) · "
        "analyze: + recon intel · pentest: + AI vuln hunting. Overrides ai.mode in ai.yaml.",
    )
    parser.add_argument(
        "--ai-two-stage",
        action="store_true",
        help="ai_pentest two-pass mode: after the first pass, run a second "
        "self-critique pass that re-verifies evidence and drops weak findings "
        "(fewer false positives, ~2x AI tokens). Overrides ai.two_stage in ai.yaml.",
    )
    parser.add_argument(
        "--ai-agentic",
        action="store_true",
        help="ai_pentest AGENTIC mode (v5): run a live observe->reason->probe loop that "
        "sends NON-destructive, in-scope requests to CONFIRM leads. Sends live traffic to "
        "your scope — authorized targets only. Overrides ai.agentic.enabled in ai.yaml.",
    )
    parser.add_argument(
        "--enumerate",
        choices=["auto", "always", "never"],
        default="auto",
        help="Subdomain enumeration. auto (default): only if scope uses a '*' "
        "wildcard; always: force subfinder; never: scan only the given hosts.",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=None,
        help="Recursive discovery depth (overrides pipeline.discovery.recursive_depth). "
        "1=single pass, 2=subdomains-of-subdomains, 100=until exhausted.",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        metavar="RUN_ID",
        help="Run only the AI stages against an EXISTING run's data (no recon). "
        "Combine with --ai-mode analyze|pentest. The run must already exist under runs/.",
    )
    parser.add_argument(
        "--log-level", default="INFO", help="Logging level (default: INFO)."
    )
    parser.add_argument(
        "--json-logs", action="store_true", help="Emit logs as JSON."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, json_logs=args.json_logs)
    log = get_logger("cli")

    domain = Domain(args.domain)
    config = ConfigLoader(Path(args.config_dir)).load()
    if args.depth is not None:
        config.pipeline.setdefault("discovery", {})["recursive_depth"] = args.depth
    if getattr(args, "ai_two_stage", False):
        config.ai["two_stage"] = True
    if getattr(args, "ai_agentic", False):
        config.ai.setdefault("agentic", {})["enabled"] = True
    load_domain(domain.value)

    if args.run_id:
        return _run_ai_only(args, config, domain, log)

    executor, tools = _build_engine(config)

    targets = list(args.target)
    if not targets:
        targets = targets_from_scope(config.scope)
        if targets:
            log.info("No CLI target(s); seeding from scope.in_scope: %s", ", ".join(targets))
    if not targets:
        log.error(
            "No targets. Pass one or more on the CLI (e.g. 'reconecoboost example.com "
            "--run') or set in_scope in config/scope.yaml."
        )
        return 2

    scope = Scope(
        targets=targets,
        in_scope=list(config.scope.get("in_scope") or []),
        out_of_scope=list(config.scope.get("out_of_scope") or []),
    )
    ctx = Context(
        domain=domain,
        scope=scope,
        config=config,
        profile=args.profile,
        executor=executor,
        tools=tools,
    )

    ai_mode = resolve_ai_mode(args, config)
    all_names = [cls.name for cls in REGISTRY.for_domain(domain)]
    enabled = _select_stages(config.profile_stages(args.profile), all_names, ai_mode)

    enumerate_subs = should_enumerate(args.enumerate, scope.in_scope)
    if not enumerate_subs:
        enabled = [s for s in enabled if s not in ENUMERATION_STAGES]

    pipeline = Pipeline.build(REGISTRY, domain=domain, enabled=enabled)

    log.info("Run %s | domain=%s | profile=%s | ai=%s | enumerate=%s",
             ctx.run_id, domain.value, args.profile, ai_mode,
             "on" if enumerate_subs else "off")
    log.info("Resolved pipeline: %s", pipeline.describe())

    if args.preflight:
        _preflight(pipeline, tools, log)

    if not args.run:
        log.info("Plan-only (use --run to execute).")
        return 0

    store: Store | None = None
    try:
        ctx.workspace = Path("runs") / ctx.run_id
        ctx.workspace.mkdir(parents=True, exist_ok=True)
        ctx.results_dir = Path("results") / ctx.run_id
        ctx.results_dir.mkdir(parents=True, exist_ok=True)
        store = Store.open(ctx.workspace / "recon.db")
        store.start_run(ctx)
        ctx.repository = store
        ctx.graph = SqliteKnowledgeGraph(store.db)
        ctx.ai = build_provider(config.ai)

        results = pipeline.run(ctx)

        statuses = {r.status.value for r in results}
        outcome = "completed" if statuses <= {"success", "skipped"} else "completed_with_errors"
        store.finish_run(ctx.run_id, outcome)

        for result in results:
            log.info(
                "  %-20s %-8s %6.3fs%s",
                result.module,
                result.status.value,
                result.duration_s,
                f" ({result.error})" if result.error else "",
            )

        stats = ctx.graph.stats(ctx.run_id)
        log.info("Graph: nodes=%s edges=%s", stats["nodes"] or "{}", stats["edges"] or "{}")
        log.info("Findings: %d", len(store.list_findings(ctx.run_id)))

        ctx.output = OutputManager(ctx.workspace)
        outputs = ctx.output.generate(store, ctx.graph, ctx.run_id)
        for fmt, path in outputs.items():
            log.info("Report (%s): %s", fmt, path)
        log.info("Raw tool output: %s/", ctx.results_dir)
        log.info("Run record: %s", ctx.workspace / "recon.db")
    finally:
        if store is not None:
            store.close()
    return 0


def _run_ai_only(args, config: Config, domain: Domain, log) -> int:
    """Run only the AI analysis stages against an existing run's stored data."""
    run_id = args.run_id
    if not re.fullmatch(r"[A-Za-z0-9._-]+", run_id):
        log.error("Invalid --run-id %r.", run_id)
        return 2
    db_path = Path("runs") / run_id / "recon.db"
    if not db_path.exists():
        log.error("No existing run at %s — run a scan first (reconecoboost ... --run).", db_path)
        return 2

    ai_mode = resolve_ai_mode(args, config)
    if ai_mode == "off":
        ai_mode = "analyze"
        log.info("--run-id needs the AI; defaulting to --ai-mode analyze.")

    store = Store.open(db_path)
    try:
        run = store.get_run(run_id) or {}
        scope_data = json.loads(run.get("scope_json") or "{}")
        scope = Scope(
            targets=scope_data.get("targets", []),
            in_scope=scope_data.get("in_scope", []),
            out_of_scope=scope_data.get("out_of_scope", []),
        )
        ctx = Context(
            domain=domain, scope=scope, config=config, run_id=run_id,
            repository=store, ai=build_provider(config.ai),
        )
        ctx.graph = SqliteKnowledgeGraph(store.db)
        ctx.workspace = Path("runs") / run_id
        # The original run's raw outputs (incl. stored response bodies the agentic
        # pentest reads, and the AI-seam files it exports) live here.
        ctx.results_dir = Path("results") / run_id
        ctx.results_dir.mkdir(parents=True, exist_ok=True)

        # Replace any prior AI findings so re-analysis doesn't pile up duplicates.
        store.clear_findings(run_id, list(ALL_AI_STAGES))

        enabled = list(AI_STAGES_BY_MODE[ai_mode])
        pipeline = Pipeline.build(REGISTRY, domain=domain, enabled=enabled)
        log.info("AI-only on existing run %s | ai=%s", run_id, ai_mode)
        log.info("Stages: %s", pipeline.describe())

        results = pipeline.run(ctx)
        for result in results:
            log.info(
                "  %-20s %-8s %6.3fs%s",
                result.module, result.status.value, result.duration_s,
                f" ({result.error})" if result.error else "",
            )

        outputs = OutputManager(ctx.workspace).generate(store, ctx.graph, run_id)
        for fmt, path in outputs.items():
            log.info("Report (%s): %s", fmt, path)
        log.info("Findings now: %d", len(store.list_findings(run_id)))
    finally:
        store.close()
    return 0


def _build_engine(config: Config) -> tuple[CommandExecutor, ToolManager]:
    """Construct the engine services from configuration and wire them together."""
    defaults = config.tools.get("defaults", {})
    retry = RetryPolicy(
        max_attempts=int(defaults.get("retries", 1)) + 1,
        backoff_s=float(defaults.get("retry_backoff_s", 2)),
    )
    executor = CommandExecutor(
        default_timeout_s=float(defaults.get("timeout_s", 600)),
        default_retry=retry,
    )
    tools = ToolManager(config.tools, executor=executor)
    return executor, tools


def _preflight(pipeline: Pipeline, tools: ToolManager, log) -> None:
    """Report availability/version of every tool used by the resolved pipeline."""
    needed = sorted({m.tool for m in pipeline.order if m.tool})
    if not needed:
        log.info("Preflight: no external tools required by this pipeline.")
        return
    report = tools.preflight(needed, strict=False)
    for name in needed:
        handle = report.get(name)
        if handle is None:
            log.warning("  %-14s MISSING", name)
        else:
            version = tools.version(name) or "unknown"
            log.info("  %-14s ok (%s) %s", name, version, handle.path)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
