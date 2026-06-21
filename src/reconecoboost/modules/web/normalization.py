"""Normalization — cross-tool consolidation pass (pure logic, no external tool).

Per-tool persistence already deduplicates entities and merges provenance. This
stage performs *cross-tool* consolidation: for every URL discovered (by katana,
gau, or ffuf) it ensures a ``host`` entity exists for the URL's origin and a
``url -> belongs_to -> host`` relation links them — so hosts found only via URLs
(without an httpx probe) still appear as graph nodes.
"""

from __future__ import annotations

from ...core.entities import Relation
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...core.module import BaseModule
from ...engine import Normalizer
from ...engine.parser import ParsedRecord
from ...orchestration.registry import register
from ..base import origin_of


@register
class Normalization(BaseModule):
    name = "normalization"
    domain = Domain.WEB
    stage = Stage.ANALYSIS
    requires = ("url", "endpoint", "technology")
    produces = ("normalized",)
    tool = None
    parser = None
    run_once = True   # consolidation — runs once after the discovery loop

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        if ctx.repository is None:
            raise NotImplementedError("persistence not available on context")

        records = []
        for asset in ctx.repository.list_assets(ctx.run_id, "url"):
            url = asset["canonical_key"]
            origin = origin_of(url)
            if origin is None:
                continue
            record = ParsedRecord("host", origin, tool="normalization")
            record.relations.append(Relation("url", url, "belongs_to", "host", origin))
            records.append(record)

        norm = Normalizer().normalize(records)
        counts = ctx.repository.persist_normalization(ctx.run_id, norm)

        result.status = ModuleStatus.SUCCESS
        result.produced = counts["assets"]
        result.meta = {"relations": counts["relations"]}
        return result
