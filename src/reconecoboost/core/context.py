"""Context — the explicit, per-run state envelope threaded into every module.

The Context replaces global state. Its *core* (identity, scope, config, service
handles) is treated as read-only after construction; the only mutable part is
the append-only result ledger. Cross-module data does NOT live here — it flows
through the database/graph (see architecture doc 07).

Service handles (executor, tools, repository, graph, ai, output) are typed as
``Any`` and default to ``None`` because those layers are not implemented in the
skeleton. They will be populated by the CLI/bootstrap once they exist.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from .models import Domain, ModuleResult
from .scope import Scope

if TYPE_CHECKING:
    from ..config.loader import Config


def _new_run_id() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Context:
    """Shared run state passed to ``BaseModule.run(ctx)``."""

    # --- read-only core -----------------------------------------------------
    domain: Domain
    scope: Scope
    config: "Config"
    profile: str = "default"
    run_id: str = field(default_factory=_new_run_id)
    created_at: datetime = field(default_factory=_now)
    workspace: Path | None = None
    results_dir: Path | None = None  # where raw tool outputs are captured

    # --- service handles (populated by bootstrap; None in the skeleton) -----
    executor: Any = None
    tools: Any = None
    repository: Any = None
    graph: Any = None
    ai: Any = None
    output: Any = None
    logger: Any = None

    # --- append-only ledger -------------------------------------------------
    results: list[ModuleResult] = field(default_factory=list)

    def add_result(self, result: ModuleResult) -> None:
        """Append a module result to the run ledger (append-only)."""
        self.results.append(result)

    def result_for(self, module_name: str) -> ModuleResult | None:
        """Return the recorded result for ``module_name`` if present."""
        for result in self.results:
            if result.module == module_name:
                return result
        return None
