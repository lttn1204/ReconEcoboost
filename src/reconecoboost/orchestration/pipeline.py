"""Pipeline — resolves the module DAG and runs it.

The pipeline derives execution order from each module's ``requires`` / ``produces``
edges (a topological sort), not from a hard-coded list. v1 ships a sequential
runner; the same resolved order feeds a future concurrent scheduler unchanged
(architecture doc 05/06/16).
"""

from __future__ import annotations

import time
from collections import deque
from typing import TYPE_CHECKING

from ..core.errors import PipelineError
from ..core.models import Domain, ModuleResult, ModuleStatus
from ..logging.setup import get_logger

if TYPE_CHECKING:
    from ..core.context import Context
    from ..core.module import BaseModule
    from .registry import ModuleRegistry


class Pipeline:
    """An ordered, dependency-resolved set of module instances."""

    def __init__(self, modules: list["BaseModule"]) -> None:
        self.modules = list(modules)
        self.order = self._resolve_order(self.modules)

    @classmethod
    def build(
        cls,
        registry: "ModuleRegistry",
        domain: Domain,
        enabled: list[str] | None = None,
    ) -> "Pipeline":
        """Construct a pipeline for ``domain`` from a registry.

        ``enabled`` (typically a profile's stage list from ``pipeline.yaml``)
        filters and is preserved as a hint; final order still comes from the DAG.
        """
        classes = registry.for_domain(domain)
        if enabled is not None:
            wanted = set(enabled)
            classes = [c for c in classes if c.name in wanted]
        return cls([cls_() for cls_ in classes])

    # -- DAG resolution -----------------------------------------------------

    @staticmethod
    def _resolve_order(modules: list["BaseModule"]) -> list["BaseModule"]:
        """Topologically sort modules by their requires/produces edges."""
        by_name = {m.name: m for m in modules}
        index = {m.name: i for i, m in enumerate(modules)}  # for stable ordering

        producers: dict[str, list[str]] = {}
        for m in modules:
            for entity in m.produces:
                producers.setdefault(entity, []).append(m.name)

        prereqs: dict[str, set[str]] = {m.name: set() for m in modules}
        for m in modules:
            for entity in m.requires:
                for producer in producers.get(entity, []):
                    if producer != m.name:
                        prereqs[m.name].add(producer)

        dependents: dict[str, list[str]] = {m.name: [] for m in modules}
        for name, deps in prereqs.items():
            for dep in deps:
                dependents[dep].append(name)

        indegree = {name: len(deps) for name, deps in prereqs.items()}
        ready = deque(
            sorted((n for n, d in indegree.items() if d == 0), key=lambda n: index[n])
        )

        order: list[str] = []
        while ready:
            name = ready.popleft()
            order.append(name)
            for child in sorted(dependents[name], key=lambda n: index[n]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)

        if len(order) != len(modules):
            unresolved = sorted(set(by_name) - set(order))
            raise PipelineError(
                f"Dependency cycle detected among modules: {unresolved}"
            )
        return [by_name[name] for name in order]

    # -- execution ----------------------------------------------------------

    def run(self, ctx: "Context") -> list[ModuleResult]:
        """Run modules in resolved order, recording each result on the context.

        A failing or not-yet-implemented module is recorded and the pipeline
        continues (fail loud, degrade gracefully — architecture doc 01).

        With the discovery loop enabled (config ``pipeline.discovery.loop``),
        the discovery/expansion modules re-run for up to ``rounds`` rounds so
        subdomains found in page content (or by brute) get resolved, crawled and
        re-mined recursively; ``run_once`` modules (findings/analysis) execute
        once at the end.
        """
        log = get_logger("pipeline", run_id=ctx.run_id)
        rounds = self._loop_rounds(ctx)

        if rounds <= 1:  # default: single pass in resolved order (unchanged)
            log.info("Running %d module(s): %s", len(self.order), self.describe())
            self._run_modules(ctx, self.order, log)
            return ctx.results

        cycle = [m for m in self.order if not getattr(m, "run_once", False)]
        finalize = [m for m in self.order if getattr(m, "run_once", False)]
        log.info("Discovery loop: up to %d round(s); cycle=[%s] finalize=[%s]",
                 rounds, ", ".join(m.name for m in cycle), ", ".join(m.name for m in finalize))

        prev = -1
        for rnd in range(1, rounds + 1):
            log.info("— discovery round %d/%d —", rnd, rounds)
            self._run_modules(ctx, cycle, log)
            count = self._subdomain_count(ctx)
            if rnd == rounds or count == prev:
                if count == prev and rnd < rounds:
                    log.info("Discovery converged after round %d (%d subdomains).", rnd, count)
                self._run_modules(ctx, finalize, log)
                break
            log.info("Round %d found %d subdomain(s) (was %d); continuing.", rnd, count, max(prev, 0))
            prev = count

        return ctx.results

    def _run_modules(self, ctx, modules, log) -> None:
        for module in modules:
            start = time.perf_counter()
            try:
                result = module.run(ctx)
                if result is None:
                    result = ModuleResult(module.name, ModuleStatus.SUCCESS)
            except NotImplementedError as exc:
                result = ModuleResult(module.name, ModuleStatus.SKIPPED, error=str(exc))
                log.warning("Module %s not implemented; skipped.", module.name)
            except Exception as exc:  # noqa: BLE001 - isolate module failures
                result = ModuleResult(module.name, ModuleStatus.FAILED, error=str(exc))
                log.exception("Module %s failed.", module.name)

            result.duration_s = round(time.perf_counter() - start, 4)
            ctx.add_result(result)

    def _subdomain_count(self, ctx) -> int:
        repo = getattr(ctx, "repository", None)
        if repo is None:
            return 0
        try:
            return len(repo.list_assets(ctx.run_id, "subdomain"))
        except Exception:  # noqa: BLE001
            return 0

    @staticmethod
    def _loop_rounds(ctx) -> int:
        cfg = ((ctx.config.pipeline.get("discovery", {}) or {}).get("loop", {}) or {})
        if not cfg.get("enabled", False):
            return 1
        try:
            return max(1, int(cfg.get("rounds", 2)))
        except (TypeError, ValueError):
            return 1

    def describe(self) -> str:
        """Human-readable resolved order, e.g. ``a -> b -> c``."""
        return " -> ".join(m.name for m in self.order)
