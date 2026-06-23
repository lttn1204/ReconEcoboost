"""Subdomain permutation with alterx, resolved by dnsx.

Brute-force (`word.<apex>`) only tries flat labels; **permutation** learns the
naming patterns already in use and mutates them — given ``api``/``dev``/``admin``
it generates ``api-dev``, ``dev-api``, ``api2``, ``admin-uat`` … — catching hosts
that a flat wordlist misses. alterx generates the candidates; dnsx resolves them;
only names that actually resolve become assets (with their IP(s) and an
``internal`` flag, like dns_resolve), and obvious wildcard-DNS noise is dropped.

Two tools are chained (alterx -> dnsx). Both are **required**: a missing binary
fails the stage (no silent skip). Runs only when the scope enumerates (it's an
ENUMERATION stage, gated on a wildcard scope) and when ``permutation.enabled``.

Declares ``produces=("permutation",)`` (a sentinel): it persists ``subdomain``
assets directly but does NOT declare producing ``subdomain``, to avoid a DAG
cycle with dns_resolve (same trick as content_subdomains / vhost_discovery).
Crawling/probing the new names is the discovery loop's job — enable
``discovery.loop`` to fully process them in the same run.

The AI seam (Phase 0): AI-suggested labels written to
``results/<run_id>/ai_subwords.txt`` are folded in as extra ``label.<apex>``
candidates, so an AI stage can later steer permutation without touching this code.
"""

from __future__ import annotations

from pathlib import Path

from ...core.errors import ToolNotFoundError
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...engine import PARSERS, Normalizer
from ...engine.executor import redact_argv
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ..base import ToolModule, host_of
from .dns_resolve import dnsx_resolver_args


@register
class Permutation(ToolModule):
    name = "permutation"
    domain = Domain.WEB
    stage = Stage.PROBING
    requires = ("subdomain",)
    produces = ("permutation",)   # persists `subdomain` directly; sentinel avoids DAG cycle
    tool = "dnsx"                  # the resolving tool (carries the rate limit + version)
    parser = "dnsx"
    input_type = "subdomain"

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        log = get_logger("module.permutation", run_id=getattr(ctx, "run_id", None))

        if not self._spec(ctx).get("enabled", True):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"disabled": True}
            return result
        # Enumeration gate: only permute on a wildcard scope (`*.domain`).
        if not self._scope_has_wildcard(ctx.scope):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"skipped": "no-wildcard-scope"}
            return result
        if ctx.executor is None or ctx.tools is None:
            raise NotImplementedError("engine services not available on context")
        if ctx.repository is None:
            raise NotImplementedError("persistence not available on context")

        # Both tools are required — a missing binary is a hard failure.
        try:
            alterx = ctx.tools.resolve("alterx")
            dnsx = ctx.tools.resolve(self.tool)
        except ToolNotFoundError as exc:
            result.status = ModuleStatus.FAILED
            result.error = str(exc)
            return result

        known = [k for k in self._gather_inputs(ctx) if self._scope_ok(ctx, k)]
        apexes = [host_of(t) or t for t in ctx.scope.targets]
        seeds = list(dict.fromkeys([*known, *apexes]))
        if not seeds:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"items": 0}
            return result

        candidates = self._generate(ctx, alterx, seeds, apexes)
        if not candidates:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"candidates": 0}
            return result

        records = self._resolve(ctx, dnsx, candidates)
        records = [r for r in records if self._record_in_scope(ctx, r)]

        produced = ctx.repository.persist_normalization(
            ctx.run_id, Normalizer().normalize(records))["assets"] if records else 0
        self._write_results(ctx, records)
        log.info(
            "permutation: %d seed(s) -> %d candidate(s) -> %d resolving subdomain(s)",
            len(seeds), len(candidates), len(records),
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = produced
        result.meta = {"seeds": len(seeds), "candidates": len(candidates),
                       "resolved": len(records)}
        return result

    # -- alterx: generate candidates ---------------------------------------

    def _generate(self, ctx, alterx, seeds: list[str], apexes: list[str]) -> list[str]:
        argv = alterx.argv("-silent")
        exec_result = ctx.executor.run(argv, timeout_s=self.timeout_s,
                                       input_text="\n".join(seeds))
        self._record_run(ctx, "alterx", argv, exec_result)
        cand: list[str] = []
        if exec_result.ok:
            cand = [ln.strip().lower() for ln in exec_result.stdout.splitlines() if ln.strip()]

        # AI seam: fold AI-suggested labels in as `label.<apex>` candidates.
        for word in self._extra_wordlist(ctx, "ai_subwords"):
            for apex in apexes:
                cand.append(f"{word}.{apex}")

        cand = list(dict.fromkeys(cand))
        cap = int(self._spec(ctx).get("max_candidates", 5000) or 0)
        if cap and len(cand) > cap:
            cand = cand[:cap]
        return cand

    # -- dnsx: resolve + drop wildcard noise -------------------------------

    def _resolve(self, ctx, dnsx, candidates: list[str]) -> list:
        probes = self._wildcard_probes(ctx)
        names = list(dict.fromkeys([*candidates, *sorted(probes)]))
        argv = dnsx.argv("-silent", "-json", "-a") + dnsx_resolver_args(ctx) + self._rate_args(ctx)
        exec_result = ctx.executor.run(argv, timeout_s=self.timeout_s,
                                       input_text="\n".join(names))
        capture_path = self._write_capture_text(ctx, "permutation-dnsx", exec_result)
        self._record_run(ctx, self.tool, argv, exec_result, capture_path)
        if not exec_result.ok:
            return []

        parsed = PARSERS.get(self.parser).parse(exec_result.stdout)
        wildcard_ips: set[str] = set()
        for r in parsed:
            if r.key in probes:
                wildcard_ips.update(r.attributes.get("ip", []))
        out = []
        for r in parsed:
            if r.key in probes:
                continue
            ips = set(r.attributes.get("ip", []))
            if wildcard_ips and ips and ips <= wildcard_ips:
                continue   # resolves only to the wildcard catch-all — false positive
            r.attributes["source"] = "permutation"
            if capture_path:
                r.raw_ref = capture_path
            out.append(r)
        return out

    @staticmethod
    def _wildcard_probes(ctx) -> set[str]:
        probes: set[str] = set()
        for target in ctx.scope.targets:
            apex = host_of(target) or target
            for i in range(3):
                probes.add(f"zzz-wildcardcheck{i}-doesnotexist.{apex}")
        return probes

    # -- output ------------------------------------------------------------

    def _write_capture_text(self, ctx, label: str, exec_result) -> str | None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None or not exec_result.ok or not exec_result.stdout:
            return None
        path = Path(results_dir) / f"{label}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(exec_result.stdout, encoding="utf-8")
        return str(path)

    def _write_results(self, ctx, records: list) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        rows = []
        for r in records:
            ips = ", ".join(r.attributes.get("ip", []))
            tag = "  [internal]" if r.attributes.get("internal") else ""
            rows.append(f"{r.key}\t{ips}{tag}")
        path = Path(results_dir) / "permutation.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        header = f"# {len(rows)} resolving permutation(s) | host <tab> IP(s) [internal]\n"
        path.write_text(header + "\n".join(sorted(rows)) + ("\n" if rows else ""), encoding="utf-8")

    def _record_run(self, ctx, tool, argv, exec_result, capture_path=None) -> None:
        if ctx.repository is None:
            return
        ctx.repository.record_tool_run(
            ctx.run_id,
            tool=tool,
            module=self.name,
            version=ctx.tools.version(tool),
            argv_redacted=redact_argv(argv),
            exit_code=exec_result.exit_code,
            status=exec_result.status.value,
            duration_s=exec_result.duration_s,
            capture_path=capture_path,
        )

    # -- config ------------------------------------------------------------

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("permutation", {}) or {})

    @staticmethod
    def _scope_has_wildcard(scope) -> bool:
        pools = list(scope.in_scope or []) + list(scope.targets or [])
        return any("*" in str(p) for p in pools)
