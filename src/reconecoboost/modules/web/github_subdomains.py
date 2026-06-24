"""GitHub code-search subdomains (github-subdomains).

Mines subdomains from PUBLIC GitHub code (configs, source, committed `.env` files)
— names that never appear in DNS or passive APIs but leak in someone's repo. A
strong complement to subfinder/brute.

Needs a **GitHub token** (read from config ``github_subdomains.token`` or the
``GITHUB_TOKEN`` env var). The token is passed via the environment, never on the
argv, so it can't leak into the tool-run audit log. Missing **token** → the stage
SKIPs (it can't do anything useful); missing **binary** → it FAILS (locked
decision for installed tools). Saved to results/<run_id>/github_subdomains.txt.
"""

from __future__ import annotations

import os
from pathlib import Path

from ...core.errors import ToolNotFoundError
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...engine import Normalizer, ParsedRecord
from ...engine.executor import redact_argv
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ..base import ToolModule, host_of


@register
class GithubSubdomains(ToolModule):
    name = "github_subdomains"
    domain = Domain.WEB
    stage = Stage.DISCOVERY
    requires = ()
    produces = ("subdomain",)
    tool = "github-subdomains"
    parser = None
    input_type = None            # seeded from scope targets, like asset_discovery

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        log = get_logger("module.github_subdomains", run_id=getattr(ctx, "run_id", None))

        if not self._spec(ctx).get("enabled", True):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"disabled": True}
            return result
        if ctx.executor is None or ctx.tools is None or ctx.repository is None:
            raise NotImplementedError("engine services / persistence not available on context")

        try:
            tool = ctx.tools.resolve(self.tool)
        except ToolNotFoundError as exc:
            result.status = ModuleStatus.FAILED   # missing binary = hard fail
            result.error = str(exc)
            return result

        env, token = self._env_with_token(ctx)
        if not token:
            result.status = ModuleStatus.SKIPPED
            result.error = "no GitHub token (set GITHUB_TOKEN or github_subdomains.token)"
            log.warning("github_subdomains: skipped — %s", result.error)
            return result

        apexes = list(dict.fromkeys(host_of(t) or t for t in ctx.scope.targets))
        results_dir = getattr(ctx, "results_dir", None)
        version = ctx.tools.version(self.tool)
        records: list = []
        for apex in apexes:
            out_file = (Path(results_dir) / f"github_subdomains-{apex}.txt") if results_dir else None
            argv = tool.argv("-d", apex, "-k")
            if out_file is not None:
                argv += ["-o", str(out_file)]
            exec_result = ctx.executor.run(argv, timeout_s=self.timeout_s, env=env)
            self._record_run(ctx, version, argv, exec_result)
            if not exec_result.ok:
                continue
            for line in self._read_subs(out_file, exec_result.stdout):
                if self._scope_ok(ctx, line):
                    records.append(ParsedRecord("subdomain", line,
                                                attributes={"source": "github"}, tool="github-subdomains"))

        records = [r for r in records if self._record_in_scope(ctx, r)]
        produced = 0
        if records:
            produced = ctx.repository.persist_normalization(
                ctx.run_id, Normalizer().normalize(records))["assets"]
        self._write_results(results_dir, records)
        log.info("github_subdomains: %d apex(es) -> %d subdomain(s)", len(apexes), len(records))
        result.status = ModuleStatus.SUCCESS
        result.produced = produced
        result.meta = {"apexes": len(apexes), "subdomains": len(records)}
        return result

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _read_subs(out_file, stdout: str) -> list[str]:
        text = ""
        if out_file is not None:
            try:
                text = out_file.read_text(encoding="utf-8")
            except OSError:
                text = ""
        if not text:
            text = stdout or ""
        return [ln.strip().lower() for ln in text.splitlines() if ln.strip() and "." in ln]

    def _env_with_token(self, ctx) -> tuple[dict, str]:
        env = dict(os.environ)
        token = str(self._spec(ctx).get("token") or "").strip()
        if token:
            env["GITHUB_TOKEN"] = token
        return env, env.get("GITHUB_TOKEN", "")

    def _write_results(self, results_dir, records) -> None:
        if results_dir is None:
            return
        names = sorted({r.key for r in records})
        path = Path(results_dir) / "github_subdomains.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {len(names)} subdomain(s) from GitHub code search\n"
                        + "\n".join(names) + ("\n" if names else ""), encoding="utf-8")

    def _record_run(self, ctx, version, argv, exec_result) -> None:
        if ctx.repository is None:
            return
        ctx.repository.record_tool_run(
            ctx.run_id, tool=self.tool, module=self.name, version=version,
            argv_redacted=redact_argv(argv), exit_code=exec_result.exit_code,
            status=exec_result.status.value, duration_s=exec_result.duration_s, capture_path=None,
        )

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("github_subdomains", {}) or {})
