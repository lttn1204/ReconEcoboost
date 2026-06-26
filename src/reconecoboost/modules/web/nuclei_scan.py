"""Vulnerability scanning with nuclei.

Runs against the live hosts discovered earlier and writes *verified* results
straight into the ``finding`` table (kind ``vulnerability``) — these are
ground-truth, unlike the AI's hypotheses. It sits in the COLLECTION stage
(after alive_detection, alongside crawling/ffuf/whatweb) and therefore runs
before the AI stages, so ai_pentest triages real findings.

Modeled as a BaseModule (not ToolModule) because it produces findings, not
assets, so it doesn't go through the asset normalizer.
"""

from __future__ import annotations

import json
from pathlib import Path

from ...core.errors import ToolNotFoundError
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...core.module import BaseModule
from ...engine.executor import redact_argv
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ..base import host_of


@register
class NucleiScan(BaseModule):
    name = "nuclei_scan"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("host",)
    produces = ("finding",)
    tool = "nuclei"
    parser = None
    run_once = True   # findings stage — runs once after the discovery loop

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        if ctx.executor is None or ctx.tools is None or ctx.repository is None:
            raise NotImplementedError("engine services / persistence not available on context")

        try:
            tool = ctx.tools.resolve(self.tool)
        except ToolNotFoundError as exc:
            result.status = ModuleStatus.SKIPPED
            result.error = str(exc)
            return result
        version = ctx.tools.version(self.tool)

        # in-scope targets (live hosts + discovered URLs) fed to nuclei on stdin
        targets = self._gather_targets(ctx)
        if not targets:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"targets": 0}
            return result

        argv = tool.argv("-silent", "-jsonl", "-duc")  # jsonl out; disable update check
        if self._spec(ctx).get("include_request_response", False):
            argv += ["-irr"]   # embed full request/response in each result (bigger output)
        argv += self._severity_args(ctx) + self._rate_args(ctx)
        exec_result = ctx.executor.run(argv, input_text="\n".join(targets), timeout_s=self._timeout(ctx))

        capture_path = self._capture(ctx, exec_result.stdout) if exec_result.ok else None
        ctx.repository.record_tool_run(
            ctx.run_id, tool=self.tool, module=self.name, version=version,
            argv_redacted=redact_argv(argv), exit_code=exec_result.exit_code,
            status=exec_result.status.value, duration_s=exec_result.duration_s,
            capture_path=capture_path,
        )
        if not exec_result.ok:
            result.status = ModuleStatus.FAILED
            result.error = f"nuclei exit {exec_result.exit_code}"
            return result

        count = self._store_findings(ctx, exec_result.stdout)
        get_logger("module.nuclei_scan", run_id=ctx.run_id).info(
            "nuclei: %d target(s) scanned, %d finding(s)", len(targets), count
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = count
        result.meta = {"targets": len(targets), "findings": count}
        return result

    # -- helpers -----------------------------------------------------------

    def _gather_targets(self, ctx) -> list[str]:
        """The root of every live, in-scope host (i.e. every alive subdomain).

        nuclei templates are root-relative, so scanning host roots covers the
        bulk of detections; individual URLs are intentionally not scanned.
        """
        seen, targets = set(), []
        for asset in ctx.repository.list_assets(ctx.run_id, "host"):
            key = asset["canonical_key"]
            if key not in seen and ctx.scope.is_allowed(host_of(key) or key):
                seen.add(key)
                targets.append(key)

        cap = self._spec(ctx).get("max_targets")
        if cap:
            targets = targets[: int(cap)]
        return targets

    def _store_findings(self, ctx, stdout: str) -> int:
        count = 0
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info") or {}
            template_id = obj.get("template-id") or obj.get("templateID")
            name = info.get("name") or template_id or "nuclei finding"
            ctx.repository.add_finding(
                ctx.run_id,
                kind="vulnerability",
                title=f"{name} [{template_id}]" if template_id else name,
                severity=info.get("severity"),
                detail={
                    "template_id": template_id,
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "type": obj.get("type"),
                    "host": obj.get("host"),
                    "matched_at": obj.get("matched-at") or obj.get("matched"),
                    # PoC to reproduce the finding by hand:
                    "curl_command": obj.get("curl-command"),
                    "matcher_name": obj.get("matcher-name"),
                    "extracted": obj.get("extracted-results"),
                    "request": obj.get("request"),    # present only when run with -irr
                    "response": obj.get("response"),  # present only when run with -irr
                    "tags": info.get("tags"),
                    "reference": info.get("reference"),
                },
                source="nuclei_scan",
            )
            count += 1
        return count

    def _capture(self, ctx, stdout: str) -> str | None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None or not stdout.strip():
            return None
        path = Path(results_dir) / "nuclei.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(stdout, encoding="utf-8")
        return str(path)

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.tools.get("tools", {}) or {}).get("nuclei", {}) or {}

    def _severity_args(self, ctx) -> list[str]:
        sev = self._spec(ctx).get("severity")
        return ["-severity", ",".join(str(s) for s in sev)] if sev else []

    def _timeout(self, ctx):
        return self._spec(ctx).get("timeout_s")  # None -> executor default

    def _rate_args(self, ctx) -> list[str]:
        tools_cfg = ctx.config.tools or {}
        spec = self._spec(ctx)
        flag = spec.get("rate_flag")
        if not flag:
            return []
        rate = spec.get("rate_limit")
        if rate is None:
            rate = (tools_cfg.get("defaults", {}) or {}).get("rate_limit")
        if not rate or rate <= 0:
            return []
        return [flag, str(int(rate))]
