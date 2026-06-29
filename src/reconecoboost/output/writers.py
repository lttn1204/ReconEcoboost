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

        self._render_top_targets(report, add)
        self._render_findings(report, add)
        self._render_pentest_guide(report, add)
        self._render_agent_log(report, add)
        self._render_params(report, add)
        self._render_assets(report, add)
        self._render_tool_runs(report, add)

        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_top_targets(report, add) -> None:
        tt = report.get("top_targets")
        if not tt:
            return
        add("## Top Targets (deterministic triage)")
        add("")
        for i, t in enumerate(tt.get("top", []), 1):
            tags = f" `[{', '.join(t.get('tags', []))}]`" if t.get("tags") else ""
            add(f"{i}. **`{t.get('key')}`** — score {t.get('score')}{tags}")
            if t.get("reasons"):
                add(f"   - {'; '.join(t['reasons'])}")
        collapsed = tt.get("collapsed") or []
        if collapsed:
            add("")
            add("**Collapsed noise clusters** (kept in DB, hidden from the shortlist):")
            for c in collapsed:
                add(f"- `{c.get('netloc')}` status={c.get('status')} len={c.get('length')} ×{c.get('count')}")
        add("")

    @staticmethod
    def _render_findings(report, add) -> None:
        findings = report.get("findings", {})
        if not findings:
            return
        add("## Findings")
        add("")
        for kind, items in findings.items():
            if kind in ("pentest_guide", "agent_log"):   # rendered as their own sections
                continue
            add(f"### {kind.replace('_', ' ').title()}")
            add("")
            for item in sorted(items, key=lambda f: _severity_rank(f.get("severity"))):
                sev = (item.get("severity") or "n/a").upper()
                score = item.get("detail", {}).get("confidence_score") if isinstance(item.get("detail"), dict) else None
                head = f"- **[{sev}] {item.get('title', '(untitled)')}**"
                if score is not None:
                    head += f" _(score {score})_"
                add(head)
                detail = item.get("detail")
                if isinstance(detail, dict):
                    for key in ("detail", "rationale", "summary"):
                        if detail.get(key):
                            add(f"  - {detail[key]}")
                    if detail.get("impact"):                    # AI pentest business impact
                        add(f"  - Impact: {detail['impact']}")
                    if detail.get("steps"):
                        add("  - Steps: " + "; ".join(str(s) for s in detail["steps"]))
                    if detail.get("test_steps"):
                        add("  - Steps: " + "; ".join(str(s) for s in detail["test_steps"]))
                    if detail.get("targets"):
                        add("  - Targets: " + ", ".join(str(t) for t in detail["targets"]))
                    if detail.get("evidence"):                  # AI pentest req/resp proof
                        add(f"  - Evidence: {detail['evidence']}")
                    # PoC / where-it-hit (nuclei + AI pentest) — reproduce by hand.
                    if detail.get("matched_at"):
                        add(f"  - Matched at: {detail['matched_at']}")
                    if detail.get("poc"):                       # AI pentest PoC
                        add(f"  - PoC: `{detail['poc']}`")
                    if detail.get("curl_command"):              # nuclei reproduce cmd
                        add(f"  - PoC: `{detail['curl_command']}`")
                    if detail.get("reference"):
                        ref = detail["reference"]
                        ref = ", ".join(ref) if isinstance(ref, list) else ref
                        add(f"  - Reference: {ref}")
            add("")

    @staticmethod
    def _render_pentest_guide(report, add) -> None:
        """AI manual-pentest dossier: stack to research + next steps to keep testing."""
        guides = report.get("findings", {}).get("pentest_guide", [])
        if not guides:
            return
        detail = guides[0].get("detail") or {}
        tech = detail.get("tech_stack") or []
        steps = detail.get("manual_next_steps") or []
        analysis = detail.get("analysis")
        if not (tech or steps or analysis):
            return

        add("## Manual Pentest Guide (AI)")
        add("")
        if tech:
            add("### Tech stack — what to check & research")
            for t in tech:
                ver = f" {t.get('version')}" if t.get("version") else ""
                add(f"- **{t.get('technology', '?')}{ver}** — {t.get('what_to_check', '')}")
                terms = t.get("search_terms") or []
                if terms:
                    add("  - Research: " + "; ".join(f"`{s}`" for s in terms))
            add("")
        if steps:
            add("### Manual next steps")
            for s in steps:
                add(f"- {s}")
            add("")
        if analysis:
            add("### AI triage notes")
            add(f"> {analysis}")
            add("")

    @staticmethod
    def _render_agent_log(report, add) -> None:
        """Agentic probe transcript: the live requests the agent ran + outcomes."""
        logs = report.get("findings", {}).get("agent_log", [])
        if not logs:
            return
        requests = (logs[0].get("detail") or {}).get("requests") or []
        if not requests:
            return
        add("## Agentic Probe Log")
        add("")
        add(f"_{len(requests)} live non-destructive request(s) the agent ran:_")
        add("")
        for r in requests:
            line = f"- `{r.get('method', 'GET')} {r.get('url', '')}`"
            if r.get("status") is not None:
                line += f" → {r['status']}"
            if r.get("location"):
                line += f" → Location: {r['location']}"
            if r.get("result"):
                line += f" → {r['result']}"
            add(line)
            if r.get("reason"):
                add(f"  - why: {r['reason']}")
        add("")

    @staticmethod
    def _render_params(report, add) -> None:
        """Manual-test surface: ready-to-test URLs + exposed API specs/GraphQL.

        Each parameterized endpoint is printed as a copy-paste URL with ``FUZZ``
        marking each injectable point, so a human can test it directly (Burp/curl)
        without a follow-up agent.
        """
        params = report.get("params", [])
        findings = report.get("findings", {})
        api_specs = findings.get("exposed_api_spec", [])
        graphql = findings.get("graphql_endpoint", [])
        if not (params or api_specs or graphql):
            return

        add("## Parameters & API Surface (for manual testing)")
        add("")
        if params:
            add("### URLs with discovered parameter(s)")
            for entry in sorted(params, key=lambda p: p.get("endpoint", "")):
                ep = entry.get("endpoint", "")
                names = entry.get("params", [])
                if not names:
                    continue
                sep = "&" if "?" in ep else "?"
                qs = "&".join(f"{n}=FUZZ" for n in names)
                add(f"- [{entry.get('method', 'GET')}] `{ep}{sep}{qs}`")
            add("")
        if api_specs:
            add("### Exposed API specs (Swagger/OpenAPI)")
            for f in api_specs:
                detail = f.get("detail") or {}
                url = detail.get("url") or f.get("title", "")
                n = detail.get("endpoints")
                suffix = f" — {n} endpoint(s)" if n is not None else ""
                add(f"- `{url}`{suffix}")
            add("")
        if graphql:
            add("### GraphQL endpoints")
            for f in graphql:
                detail = f.get("detail") or {}
                add(f"- `{detail.get('url') or f.get('title', '')}`")
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
