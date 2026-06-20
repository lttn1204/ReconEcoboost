"""Secret scanning — regex-scan fetched JS/JSON bodies for exposed secrets.

Inspired by leaklens. The bodies are fetched once by ``js_fetch``; this stage
just reads them (no second network pass) and runs a deterministic rule engine
(``analysis.secrets``). Matches are redacted before storage. No LLM, zero tokens.
Emits ``finding(kind="secret")``, which triage promotes into the curated AI
context.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...analysis.secrets import scan_text
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...core.module import BaseModule
from ...logging.setup import get_logger
from ...orchestration.registry import register
from .js_fetch import load_bodies


@register
class SecretScan(BaseModule):
    name = "secret_scan"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("response",)   # bodies fetched by js_fetch
    produces = ("finding",)
    tool = None
    parser = None

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        if ctx.repository is None:
            raise NotImplementedError("persistence not available on context")

        bodies = load_bodies(getattr(ctx, "results_dir", None))
        if not bodies:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"bodies": 0}
            return result

        findings = self._scan(ctx, bodies)
        count = self._store(ctx, findings)
        self._write_results(ctx, findings)
        get_logger("module.secret_scan", run_id=ctx.run_id).info(
            "secret_scan: %d body(ies) scanned, %d secret(s) found", len(bodies), count
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = count
        result.meta = {"bodies": len(bodies), "secrets": count}
        return result

    # -- helpers -----------------------------------------------------------

    def _scan(self, ctx, bodies: list[tuple[str, str]]) -> list[dict]:
        ent = self._spec(ctx).get("entropy", {}) or {}
        scan_kwargs = {
            "entropy": bool(ent.get("enabled", False)),
            "base64_threshold": float(ent.get("base64_threshold", 4.5)),
            "hex_threshold": float(ent.get("hex_threshold", 3.0)),
            "entropy_min_length": int(ent.get("min_length", 20)),
        }
        findings: list[dict] = []
        for url, body in bodies:
            for match in scan_text(body, **scan_kwargs):
                findings.append({
                    "url": url, "rule": match.rule, "severity": match.severity,
                    "redacted": match.redacted, "line": match.line,
                })
        return findings

    def _store(self, ctx, findings: list[dict]) -> int:
        for f in findings:
            ctx.repository.add_finding(
                ctx.run_id, kind="secret",
                title=f"{f['rule']} exposed in {f['url']}",
                severity=f["severity"],
                detail={"rule": f["rule"], "url": f["url"],
                        "match_redacted": f["redacted"], "line": f["line"]},
                source="secret_scan",
            )
        return len(findings)

    def _write_results(self, ctx, findings: list[dict]) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        out = Path(results_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "secrets.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")
        lines = [
            f"[{f['severity'].upper()}] {f['rule']}  {f['url']}:{f['line']}  -> {f['redacted']}"
            for f in findings
        ]
        (out / "secrets.txt").write_text(("\n".join(lines) + "\n") if lines else "(no secrets found)\n",
                                         encoding="utf-8")

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("secret_scan", {}) or {})
