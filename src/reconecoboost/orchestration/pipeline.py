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
        """
        log = get_logger("pipeline", run_id=ctx.run_id)
        log.info("Running %d module(s): %s", len(self.order), self.describe())

        for module in self.order:
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

        return ctx.results

    def describe(self) -> str:
        """Human-readable resolved order, e.g. ``a -> b -> c``."""
        return " -> ".join(m.name for m in self.order)
