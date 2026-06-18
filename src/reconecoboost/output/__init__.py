"""Output management layer (architecture doc 15).

Builds run deliverables (JSON / Markdown / HTML) from the durable store + graph,
decoupled from execution so reports are reproducible and re-renderable.
"""

from .manager import DEFAULT_FORMATS, OutputManager
from .report import build_report
from .writers import (
    HtmlReportWriter,
    JsonReportWriter,
    MarkdownReportWriter,
    ReportWriter,
    WRITERS,
)

__all__ = [
    "OutputManager",
    "DEFAULT_FORMATS",
    "build_report",
    "ReportWriter",
    "JsonReportWriter",
    "MarkdownReportWriter",
    "HtmlReportWriter",
    "WRITERS",
]
