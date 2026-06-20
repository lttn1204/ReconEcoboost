"""Shared JS/JSON fetch — fetch discovered web bodies ONCE with httpx.

Both ``secret_scan`` and ``js_intel`` need the response bodies of the discovered
JS/JSON (and live) URLs. Rather than each fetching independently, this stage
fetches once, writes each body to ``results/<run_id>/responses/`` and an
``index.json`` mapping URL → file. Downstream modules read those via
``load_bodies`` — no second network pass.
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

_DEFAULT_EXTS = ("js", "json", "map", "txt", "xml", "yml", "yaml", "env", "config", "bak")
# Binary/media we never fetch, even if they return 200.
_SKIP_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tif",
              ".tiff", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi",
              ".mov", ".webm", ".wasm", ".css")


def _attrs(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _status_of(attrs: dict):
    """Best status for a URL: url_probe's `status_code`, else ffuf's GET method."""
    if attrs.get("status_code") is not None:
        return attrs["status_code"]
    methods = attrs.get("methods") or {}
    get = methods.get("GET") or {}
    if get.get("status") is not None:
        return get["status"]
    for info in methods.values():
        if (info or {}).get("status") is not None:
            return info["status"]
    return None


def load_bodies(results_dir) -> list[tuple[str, str]]:
    """Read (url, body) pairs that js_fetch stored for this run."""
    if results_dir is None:
        return []
    index = Path(results_dir) / "responses" / "index.json"
    if not index.exists():
        return []
    try:
        entries = json.loads(index.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    out: list[tuple[str, str]] = []
    for entry in entries:
        url, fname = entry.get("url"), entry.get("file")
        if not url or not fname:
            continue
        try:
            out.append((url, (index.parent / fname).read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    return out


@register
class JsFetch(BaseModule):
    name = "js_fetch"
    domain = Domain.WEB
    stage = Stage.COLLECTION
    requires = ("url",)
    produces = ("response",)   # consumed by secret_scan + js_intel
    tool = "httpx"
    parser = None

    def run(self, ctx) -> ModuleResult:
        result = ModuleResult(self.name)
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
            result.status = ModuleStatus.SKIPPED
            result.error = str(exc)
            return result
        version = ctx.tools.version(self.tool)

        urls = self._gather_urls(ctx)
        results_dir = getattr(ctx, "results_dir", None)
        if not urls or results_dir is None:
            result.status = ModuleStatus.SUCCESS
            result.meta = {"urls": len(urls)}
            return result

        responses_dir = Path(results_dir) / "responses"
        responses_dir.mkdir(parents=True, exist_ok=True)
        argv = (tool.argv("-silent", "-json", "-include-response",
                          "-store-response", "-store-response-dir", str(responses_dir))
                + self._rate_args(ctx))
        exec_result = ctx.executor.run(argv, input_text="\n".join(urls), timeout_s=spec.get("timeout_s"))
        ctx.repository.record_tool_run(
            ctx.run_id, tool=self.tool, module=self.name, version=version,
            argv_redacted=redact_argv(argv), exit_code=exec_result.exit_code,
            status=exec_result.status.value, duration_s=exec_result.duration_s, capture_path=None,
        )
        if not exec_result.ok:
            result.status = ModuleStatus.FAILED
            result.error = f"httpx exit {exec_result.exit_code}"
            return result

        index = self._store_bodies(exec_result.stdout, responses_dir)
        get_logger("module.js_fetch", run_id=ctx.run_id).info(
            "js_fetch: %d url(s) requested, %d body(ies) stored", len(urls), len(index)
        )
        result.status = ModuleStatus.SUCCESS
        result.produced = len(index)
        result.meta = {"urls": len(urls), "fetched": len(index)}
        return result

    # -- helpers -----------------------------------------------------------

    def _gather_urls(self, ctx) -> list[str]:
        spec = self._spec(ctx)
        exts = tuple("." + e.lstrip(".") for e in spec.get("extensions", _DEFAULT_EXTS))
        scan_status = {int(s) for s in spec.get("scan_status", [200]) or []}
        cap = int(spec.get("max_urls", 500) or 0)
        seen, out = set(), []
        for asset in ctx.repository.list_assets(ctx.run_id, "url"):
            key = asset["canonical_key"]
            path = key.split("?", 1)[0].split("#", 1)[0].lower()
            if path.endswith(_SKIP_EXTS):
                continue
            ext_ok = path.endswith(exts)
            status_ok = False
            if scan_status and not ext_ok:
                status_ok = _status_of(_attrs(asset.get("attributes_json"))) in scan_status
            if not (ext_ok or status_ok) or key in seen:
                continue
            if ctx.scope.is_allowed(host_of(key) or key):
                seen.add(key)
                out.append(key)
        return out[:cap] if cap else out

    def _store_bodies(self, stdout: str, responses_dir: Path) -> list[dict]:
        index: list[dict] = []
        for i, line in enumerate(stdout.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or obj.get("input")
            body = self._body(obj)
            if not url or not body:
                continue
            fname = f"body-{i:04d}.txt"
            (responses_dir / fname).write_text(body, encoding="utf-8")
            index.append({"url": url, "file": fname})
        (responses_dir / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")
        return index

    @staticmethod
    def _body(obj: dict) -> str:
        for field_name in ("response", "body", "raw"):
            value = obj.get(field_name)
            if isinstance(value, str) and value:
                return value
        stored = obj.get("stored_response_path")
        if stored:
            try:
                return Path(stored).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                return ""
        return ""

    @staticmethod
    def _spec(ctx) -> dict:
        return (ctx.config.pipeline.get("js_fetch", {}) or {})

    def _rate_args(self, ctx) -> list[str]:
        tools_cfg = ctx.config.tools or {}
        hx = (tools_cfg.get("tools", {}) or {}).get("httpx", {}) or {}
        flag = hx.get("rate_flag")
        if not flag:
            return []
        rate = hx.get("rate_limit")
        if rate is None:
            rate = (tools_cfg.get("defaults", {}) or {}).get("rate_limit")
        if not rate or rate <= 0:
            return []
        return [flag, str(int(rate))]
