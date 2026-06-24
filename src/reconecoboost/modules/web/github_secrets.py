"""GitHub leaked-secret discovery (trufflehog).

Scans an organization's / specific repositories' GitHub history for committed
secrets (API keys, DB creds, tokens). GitHub leaks are often higher severity than
JS leaks — they're real credentials. trufflehog **verifies** each find against the
provider by default (a live key vs a dead string), which cuts false positives hard.

trufflehog works per **org/repo**, not by domain search, so the org(s)/repo(s) must
be configured (``github_secrets.orgs`` / ``.repos``). With ``auto_org: true`` it also
guesses the org from the apex label (e.g. ``lpbank.com.vn`` → ``lpbank``) — off by
default so it never scans an unrelated third-party org silently. Needs a GitHub
token (config or ``GITHUB_TOKEN``, passed via env, never on argv).

Findings → kind ``secret`` (source ``github_secrets``), full value stored by default
(``redact: true`` to mask). Saved to results/<run_id>/github_secrets.{txt,json}.
OSINT note: verification pings the provider; set ``verify: false`` to stay passive.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ...analysis.secrets import redact
from ...core.errors import ToolNotFoundError
from ...core.models import Domain, ModuleResult, ModuleStatus, Stage
from ...engine.executor import redact_argv
from ...logging.setup import get_logger
from ...orchestration.registry import register
from ..base import ToolModule, host_of


@register
class GithubSecrets(ToolModule):
    name = "github_secrets"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ()
    produces = ("finding",)
    tool = "trufflehog"
    parser = None
    input_type = None
    run_once = True

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
        log = get_logger("module.github_secrets", run_id=getattr(ctx, "run_id", None))
        spec = self._spec(ctx)

        if not spec.get("enabled", True):
            result.status = ModuleStatus.SUCCESS
            result.meta = {"disabled": True}
            return result
        if ctx.executor is None or ctx.tools is None or ctx.repository is None:
            raise NotImplementedError("engine services / persistence not available on context")

        try:
            tool = ctx.tools.resolve(self.tool)
        except ToolNotFoundError as exc:
            result.status = ModuleStatus.FAILED
            result.error = str(exc)
            return result

        env, token = self._env_with_token(ctx)
        if not token:
            result.status = ModuleStatus.SKIPPED
            result.error = "no GitHub token (set GITHUB_TOKEN or github_secrets.token)"
            log.warning("github_secrets: skipped — %s", result.error)
            return result

        orgs, repos = self._targets(ctx)
        if not orgs and not repos:
            result.status = ModuleStatus.SKIPPED
            result.error = ("no org/repo configured — set github_secrets.orgs / .repos "
                            "(or auto_org: true)")
            log.warning("github_secrets: skipped — %s", result.error)
            return result

        argv = tool.argv("github", "--json", "--no-update")
        if not spec.get("verify", True):
            argv.append("--no-verification")
        argv += ["--results", str(spec.get("results", "verified,unknown"))]
        for org in orgs:
            argv += ["--org", org]
        for repo in repos:
            argv += ["--repo", repo]

        exec_result = ctx.executor.run(argv, timeout_s=float(spec.get("timeout_s", 1800)), env=env)
        self._record_run(ctx, ctx.tools.version(self.tool), argv, exec_result)
        if not exec_result.ok and not exec_result.stdout:
            result.status = ModuleStatus.FAILED
            result.error = f"trufflehog exit {exec_result.exit_code}"
            return result

        findings = self._parse(exec_result.stdout, redact_on=bool(spec.get("redact", False)))
        for f in findings:
            ctx.repository.add_finding(ctx.run_id, source=self.name, **f)
        self._write_results(ctx, findings, orgs, repos)
        log.info("github_secrets: scanned org=%s repo=%s -> %d secret(s)",
                 ",".join(orgs) or "-", ",".join(repos) or "-", len(findings))
        result.status = ModuleStatus.SUCCESS
        result.produced = len(findings)
        result.meta = {"orgs": orgs, "repos": repos, "secrets": len(findings)}
        return result

    # -- parse trufflehog json (log lines mixed with finding lines) --------

    @staticmethod
    def _parse(stdout: str, *, redact_on: bool) -> list[dict]:
        out, seen = [], set()
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line or '"DetectorName"' not in line:
                continue   # skip trufflehog's info/log lines
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            detector = d.get("DetectorName") or "unknown"
            verified = bool(d.get("Verified"))
            raw = d.get("Raw") or d.get("RawV2") or ""
            gh = ((d.get("SourceMetadata") or {}).get("Data") or {}).get("Github") or {}
            repo = gh.get("repository") or ""
            file = gh.get("file") or ""
            link = gh.get("link") or ""
            key = (detector, repo, file, raw)
            if key in seen:
                continue
            seen.add(key)
            value = redact(raw) if (redact_on and raw) else raw
            out.append({
                "kind": "secret",
                "severity": "high" if verified else "medium",
                "title": f"{detector} secret in GitHub {repo}" + (" (VERIFIED)" if verified else ""),
                "detail": {"detector": detector, "verified": verified, "repository": repo,
                           "file": file, "link": link, "match": value},
            })
        return out

    # -- targets / token ---------------------------------------------------

    def _targets(self, ctx) -> tuple[list[str], list[str]]:
        spec = self._spec(ctx)
        orgs = [str(o).strip() for o in (spec.get("orgs") or []) if str(o).strip()]
        repos = [str(r).strip() for r in (spec.get("repos") or []) if str(r).strip()]
        if not orgs and spec.get("auto_org", False):
            for target in ctx.scope.targets:
                apex = host_of(target) or target
                label = apex.split(".")[0]
                if label and label not in orgs:
                    orgs.append(label)
        return list(dict.fromkeys(orgs)), list(dict.fromkeys(repos))

    def _env_with_token(self, ctx) -> tuple[dict, str]:
        env = dict(os.environ)
        token = str(self._spec(ctx).get("token") or "").strip()
        if token:
            env["GITHUB_TOKEN"] = token
        return env, env.get("GITHUB_TOKEN", "")

    # -- output ------------------------------------------------------------

    def _write_results(self, ctx, findings, orgs, repos) -> None:
        results_dir = getattr(ctx, "results_dir", None)
        if results_dir is None:
            return
        rows = []
        for f in findings:
            d = f["detail"]
            rows.append(f"[{f['severity'].upper()}] {d['detector']} "
                        f"{d['repository']}/{d['file']} -> {d['match']}")
        path = Path(results_dir) / "github_secrets.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# github_secrets — {len(findings)} secret(s) | orgs={orgs} repos={repos}\n"
                        + "\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
        (Path(results_dir) / "github_secrets.json").write_text(
            json.dumps(findings, indent=2), encoding="utf-8")

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
        return (ctx.config.pipeline.get("github_secrets", {}) or {})
