"""Report writers — render a report dict into a deliverable format.

Each writer is a pure function of (report, path). Adding a new format is a new
writer; existing writers and the report builder are untouched (architecture
doc 15).
"""

from __future__ import annotations

import html
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class ReportWriter(ABC):
    extension: str = ""

    @abstractmethod
    def render(self, report: dict[str, Any]) -> str:
        """Render the report to a string."""

    def write(self, report: dict[str, Any], path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(report), encoding="utf-8")
        return path


class JsonReportWriter(ReportWriter):
    extension = "json"

    def render(self, report: dict[str, Any]) -> str:
        return json.dumps(report, indent=2, sort_keys=True, default=str)


def _severity_rank(value: str | None) -> int:
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return order.get((value or "").lower(), 4)


class MarkdownReportWriter(ReportWriter):
    extension = "md"

    def render(self, report: dict[str, Any]) -> str:
        run = report.get("run", {})
        lines: list[str] = []
        add = lines.append

        add(f"# ReconEcoboost Report — {run.get('domain', '?')} run")
        add("")
        add(f"- **Run ID:** `{run.get('id', '?')}`")
        add(f"- **Profile:** {run.get('profile', '?')}")
        add(f"- **Status:** {run.get('status', '?')}")
        add(f"- **Created:** {run.get('created_at', '?')}")
        add(f"- **Finished:** {run.get('finished_at', '?')}")
        add(f"- **Targets:** {', '.join(report.get('targets', [])) or '(none)'}")
        add("")

        add("## Overview")
        add("")
        counts = report.get("asset_counts", {})
        if counts:
            for atype, n in sorted(counts.items()):
                add(f"- {atype}: {n}")
        else:
            add("- No assets discovered.")
        add(f"- relations: {report.get('relation_count', 0)}")
        add(f"- findings: {report.get('finding_count', 0)}")
        add("")

        self._render_findings(report, add)
        self._render_assets(report, add)
        self._render_tool_runs(report, add)

        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_findings(report, add) -> None:
        findings = report.get("findings", {})
        if not findings:
            return
        add("## Findings")
        add("")
        for kind, items in findings.items():
            add(f"### {kind.replace('_', ' ').title()}")
            add("")
            for item in sorted(items, key=lambda f: _severity_rank(f.get("severity"))):
                sev = (item.get("severity") or "n/a").upper()
                add(f"- **[{sev}] {item.get('title', '(untitled)')}**")
                detail = item.get("detail")
                if isinstance(detail, dict):
                    for key in ("detail", "rationale", "summary"):
                        if detail.get(key):
                            add(f"  - {detail[key]}")
                    if detail.get("steps"):
                        add("  - Steps: " + "; ".join(str(s) for s in detail["steps"]))
                    if detail.get("targets"):
                        add("  - Targets: " + ", ".join(str(t) for t in detail["targets"]))
            add("")

    @staticmethod
    def _render_assets(report, add) -> None:
        assets = report.get("assets", {})
        if not assets:
            return
        add("## Assets")
        add("")
        for atype in sorted(assets):
            items = assets[atype]
            add(f"### {atype} ({len(items)})")
            add("")
            for record in items:
                add(f"- `{record.get('canonical_key')}`")
            add("")

    @staticmethod
    def _render_tool_runs(report, add) -> None:
        tool_runs = report.get("tool_runs", [])
        if not tool_runs:
            return
        add("## Tool Runs")
        add("")
        add("| tool | status | exit | duration (s) |")
        add("|---|---|---|---|")
        for tr in tool_runs:
            add(
                f"| {tr.get('tool')} | {tr.get('status')} | "
                f"{tr.get('exit_code')} | {tr.get('duration_s')} |"
            )
        add("")


class HtmlReportWriter(ReportWriter):
    extension = "html"

    def render(self, report: dict[str, Any]) -> str:
        run = report.get("run", {})
        body = MarkdownReportWriter().render(report)
        # Minimal, dependency-free HTML wrapping the Markdown source in <pre>.
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>ReconEcoboost — {html.escape(str(run.get('id', '')))}</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;"
            "padding:0 1rem}pre{white-space:pre-wrap;line-height:1.4}</style></head>"
            f"<body><pre>{html.escape(body)}</pre></body></html>\n"
        )


WRITERS: dict[str, ReportWriter] = {
    "json": JsonReportWriter(),
    "markdown": MarkdownReportWriter(),
    "html": HtmlReportWriter(),
}
