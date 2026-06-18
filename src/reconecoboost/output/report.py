"""Report assembly — build a structured report from the durable store.

Reports derive entirely from the database + graph, never from module return
values, so they are reproducible and re-renderable without re-running tools
(architecture doc 15).
"""

from __future__ import annotations

import json
from typing import Any


def _parse(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def build_report(store, graph, run_id: str) -> dict[str, Any]:
    """Assemble a serializable report dict for ``run_id``."""
    run = store.get_run(run_id) or {}
    scope = _parse(run.get("scope_json"), {})

    assets_by_type: dict[str, list[dict]] = {}
    for asset in store.list_assets(run_id):
        record = dict(asset)
        record["attributes"] = _parse(record.pop("attributes_json", None), {})
        assets_by_type.setdefault(record["asset_type"], []).append(record)
    asset_counts = {atype: len(items) for atype, items in assets_by_type.items()}

    findings_by_kind: dict[str, list[dict]] = {}
    finding_count = 0
    for finding in store.list_findings(run_id):
        record = dict(finding)
        record["detail"] = _parse(record.pop("detail_json", None), None)
        findings_by_kind.setdefault(record["kind"], []).append(record)
        finding_count += 1

    relations = store.list_relations(run_id)
    tool_runs = store.list_tool_runs(run_id)
    graph_stats = graph.stats(run_id) if graph is not None else {"nodes": {}, "edges": {}}

    return {
        "run": run,
        "targets": scope.get("targets", []),
        "scope": scope,
        "asset_counts": asset_counts,
        "assets": assets_by_type,
        "relation_count": len(relations),
        "relations": relations,
        "finding_count": finding_count,
        "findings": findings_by_kind,
        "tool_runs": tool_runs,
        "graph": graph_stats,
    }
