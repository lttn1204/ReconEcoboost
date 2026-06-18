"""Screenshot capture (future: gowitness). Optional stub only."""

from __future__ import annotations

from ...core.context import Context
from ...core.models import Domain, ModuleResult, Stage
from ...core.module import BaseModule
from ...orchestration.registry import register


@register
class Screenshot(BaseModule):
    name = "screenshot"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("host",)
    produces = ("artifact",)
    tool = None  # tool wired in a later version (e.g. gowitness)
    parser = None
    optional = True

    def run(self, ctx: Context) -> ModuleResult:
        raise NotImplementedError("recon logic not implemented in skeleton")
