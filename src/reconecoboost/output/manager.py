"""OutputManager — produce run deliverables into the run workspace.

Builds the report once from the store + graph, then writes each requested format
to ``<workspace>/report.<ext>``. Decoupled from execution: it can be re-run on a
finished engagement without touching tools (architecture doc 15).
"""

from __future__ import annotations

from pathlib import Path

from ..core.errors import ReconEcoboostError
from .report import build_report
from .writers import WRITERS

DEFAULT_FORMATS = ("json", "markdown", "html")


class OutputManager:
    def __init__(self, workspace: str | Path) -> None:
        self.workspace = Path(workspace)

    def generate(
        self,
        store,
        graph,
        run_id: str,
        formats: tuple[str, ...] = DEFAULT_FORMATS,
    ) -> dict[str, Path]:
        """Build the report and write the requested formats. Returns format -> path."""
        report = build_report(store, graph, run_id)
        outputs: dict[str, Path] = {}
        for fmt in formats:
            writer = WRITERS.get(fmt)
            if writer is None:
                raise ReconEcoboostError(f"Unknown report format: '{fmt}'")
            path = self.workspace / f"report.{writer.extension}"
            outputs[fmt] = writer.write(report, path)
        return outputs
