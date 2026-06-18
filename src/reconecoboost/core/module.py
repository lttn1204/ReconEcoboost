"""BaseModule — the plugin contract every recon/analysis stage implements.

A module is *declarative about its place in the pipeline* (class attributes) and
*imperative only inside* :meth:`run`. Dependencies between stages are expressed
through ``requires`` / ``produces`` against the canonical entity taxonomy, never
by naming other modules — this is what makes stages independently replaceable
(see architecture doc 06).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, TYPE_CHECKING

from .models import Domain, ModuleResult, Stage

if TYPE_CHECKING:  # avoid a runtime import cycle; Context only needed for typing
    from .context import Context


class BaseModule(ABC):
    """Abstract base for all pipeline modules.

    Subclasses set the class-level attributes below and implement :meth:`run`.
    They must not call ``subprocess`` directly, reach for global state, or talk
    to the LLM with raw output — those concerns belong to the engine services
    threaded in via the :class:`Context`.
    """

    #: Unique, stable identifier (e.g. ``"asset_discovery"``).
    name: ClassVar[str] = ""
    #: Recon domain this module belongs to.
    domain: ClassVar[Domain] = Domain.WEB
    #: Logical stage category.
    stage: ClassVar[Stage] = Stage.DISCOVERY
    #: Canonical entity types this module consumes.
    requires: ClassVar[tuple[str, ...]] = ()
    #: Canonical entity types this module produces.
    produces: ClassVar[tuple[str, ...]] = ()
    #: Logical tool name resolved via ToolManager, or ``None`` for pure logic.
    tool: ClassVar[str | None] = None
    #: Logical parser name for this tool's output, or ``None``.
    parser: ClassVar[str | None] = None
    #: If ``True``, a failure here does not block dependent stages.
    optional: ClassVar[bool] = False

    @abstractmethod
    def run(self, ctx: "Context") -> ModuleResult:
        """Execute the stage.

        Implementations receive the shared run :class:`Context`, perform their
        work via the engine services it carries, persist results to the store,
        and return a :class:`ModuleResult`. Not implemented in the skeleton.
        """
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{type(self).__name__} name={self.name!r} stage={self.stage.value}>"
